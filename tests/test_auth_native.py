"""Native login contracts with trusted-provider fixtures; no network or real users."""
from copy import deepcopy
import base64
import hashlib
import hmac
import json

import pytest

from test_auth_boundary import Api, CognitoError, Store, jwt
from web_service.auth_service import CLIENT, ISSUER, BROWSER_COOKIE, SESSION_COOKIE
from web_service.auth_sessions import DynamoAuthStore, key
from web_service.auth_native import CognitoNative
from web_service.auth_native_trigger import customize, POOL, REGION

LOGIN = "nativeLoginFixture123"
SIGNUP = "signupFixtureClient456"
SECRET = "fixture-secret-not-real-123456789"
EMAIL = "user@example.com"
SUB = "01234567-0123-0123-0123-012345678901"


def id_token(now, **changes):
    claims = {"iss": ISSUER, "aud": LOGIN, "token_use": "id", "sub": SUB,
              "email": EMAIL, "email_verified": True, "exp": now + 300, **changes}
    enc = lambda value: base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return enc({"alg": "RS256", "kid": "mock-provider"}) + "." + enc(claims) + ".mock"


class Cognito:
    def __init__(self, clock):
        self.clock, self.calls, self.revoked = clock, [], []
        self.on_auth = None
        self.error = None
        self.challenge = False
        self.access_changes, self.id_changes = {}, {}

    def initiate_auth(self, **request):
        self.calls.append(request)
        hook, self.on_auth = self.on_auth, None
        if hook:
            hook()
        if self.error:
            raise self.error
        if self.challenge:
            return {"ChallengeName": "NEW_PASSWORD_REQUIRED", "Session": "private-challenge"}
        result = {"AccessToken": jwt(self.clock[0], client_id=LOGIN, scope="team5-web/analysis",
                                    exp=self.clock[0] + 300, **self.access_changes),
                  "IdToken": id_token(self.clock[0], **self.id_changes), "ExpiresIn": 300, "TokenType": "Bearer"}
        if request["AuthFlow"] == "USER_PASSWORD_AUTH":
            result["RefreshToken"] = "native-refresh-" + str(len(self.calls))
        return {"AuthenticationResult": result}

    def revoke_token(self, **request):
        self.revoked.append(request)
        return {}


class NativeApi(Api):
    def __init__(self):
        super().__init__()
        self.cognito = Cognito(self.clock)
        self.native = CognitoNative(self.cognito, LOGIN, SECRET, signup_client_id=SIGNUP)
        self.app.native = self.native

    def signin(self, **body):
        return self.call("/api/auth/signin", "POST", {"email": EMAIL, "password": "existing-password!", **body})

    def bind(self):
        response, value = self.signin()
        assert response["statusCode"] == 409 and value["code"] == "signin_binding_required"
        assert not self.cognito.calls


def test_first_signin_only_binds_then_session_restores_without_password_or_refresh_in_browser():
    api = NativeApi()
    api.bind()
    response, value = api.signin(email=" USER@EXAMPLE.COM ")
    assert response["statusCode"] == 200 and set(value) == {"authenticated", "access_token", "expires_at", "session_ref"}
    assert "no-store" in response["headers"]["cache-control"]
    assert "location" not in response["headers"]
    assert all("HttpOnly" in c and "Secure" in c and "Path=/" in c and "Domain=" not in c
               for c in response["multiValueHeaders"]["Set-Cookie"])
    row = api.store.read(key("SESSION", api.cookies[SESSION_COOKIE]))
    assert row["provider_kind"] == "native" and row["provider_client_id"] == LOGIN
    assert row["expires_at"] == api.clock[0] + 86340
    assert "id_token" not in row and "password" not in json.dumps(api.store.rows)
    assert "native-refresh" not in response["body"] and SECRET not in json.dumps(response)
    assert api.call("/api/auth/session")[1] == value
    assert len(api.cognito.calls) == 1
    serializer = DynamoAuthStore(None, "fixture")
    assert all(serializer.encode(v) for v in api.store.rows.values())


@pytest.mark.parametrize("headers", [{"origin": "https://attacker.invalid"}, {"x-linkguard-request": ""}, {"content-type": "text/plain"}])
def test_native_csrf_rejected_before_binding_or_provider(headers):
    api = NativeApi()
    response, _ = api.call("/api/auth/signin", "POST", {"email": EMAIL, "password": "x"}, headers)
    assert response["statusCode"] == 403 and not api.store.rows and not api.cognito.calls


def test_invalid_body_and_missing_server_source_ip_make_no_writes():
    api = NativeApi()
    for body in ({"email": EMAIL}, {"email": EMAIL, "password": None}, {"email": EMAIL, "password": "x", "client_id": LOGIN}):
        response, _ = api.call("/api/auth/signin", "POST", body)
        assert response["statusCode"] == 400
    event = {"httpMethod": "POST", "path": "/api/auth/signin", "headers": {
        "origin": "https://d2gmygchoew9ed.cloudfront.net", "x-linkguard-request": "v1", "content-type": "application/json",
        "x-forwarded-for": "203.0.113.25"}, "body": json.dumps({"email": EMAIL, "password": "x"})}
    assert api.app.handle(event)["statusCode"] == 503
    assert not api.store.rows and not api.cognito.calls


@pytest.mark.parametrize("code", ["UserNotFoundException", "NotAuthorizedException", "UserNotConfirmedException", "PasswordResetRequiredException"])
def test_account_state_errors_share_one_non_enumerating_response(code):
    api = NativeApi(); api.bind(); api.cognito.error = CognitoError(code)
    response, value = api.signin()
    assert response["statusCode"] == 401
    assert value == {"code": "invalid_credentials", "message": "이메일 또는 비밀번호를 확인해 주세요."}
    assert not any(k.startswith("SESSION#") for k in api.store.rows)
    assert code not in json.dumps(response)


def test_challenge_is_not_a_session_and_timeout_is_not_automatically_retried():
    api = NativeApi(); api.bind(); api.cognito.challenge = True
    assert api.signin()[0]["statusCode"] == 401
    api.cognito.challenge = False; api.cognito.error = TimeoutError("submitted-secret-must-not-escape")
    response, value = api.signin()
    assert response["statusCode"] == 503 and value["code"] == "signin_unavailable"
    assert "submitted-secret" not in json.dumps(response) and len(api.cognito.calls) == 2


def test_password_auth_hmac_email_and_refresh_hmac_sub_not_email():
    api = NativeApi(); api.bind(); _, accepted = api.signin()
    expected = lambda username: base64.b64encode(hmac.new(SECRET.encode(), (username + LOGIN).encode(), hashlib.sha256).digest()).decode()
    assert api.cognito.calls[0]["AuthParameters"]["SECRET_HASH"] == expected(EMAIL)
    api.clock[0] += 241
    response, refreshed = api.call("/api/auth/session")
    assert response["statusCode"] == 200 and refreshed["session_ref"] == accepted["session_ref"]
    request = api.cognito.calls[1]
    assert request["ClientId"] == LOGIN and request["AuthFlow"] == "REFRESH_TOKEN_AUTH"
    assert request["AuthParameters"] == {"REFRESH_TOKEN": "native-refresh-1", "SECRET_HASH": expected(SUB)}
    assert not any(c[0] == "refresh" for c in api.provider.calls)


@pytest.mark.parametrize("field,value", [("aud", CLIENT), ("sub", "different-sub"), ("iss", "https://wrong.invalid"),
                                          ("token_use", "access"), ("email_verified", False), ("email_verified", "true"),
                                          ("email", "other@example.com"), ("exp", 1)])
def test_native_id_claim_failures_revoke_and_do_not_create_session(field, value):
    api = NativeApi(); api.bind(); api.cognito.id_changes[field] = value
    response, result = api.signin()
    assert response["statusCode"] == 503 and "access_token" not in result
    assert not any(k.startswith("SESSION#") for k in api.store.rows)
    assert api.cognito.revoked[-1]["Token"] == "native-refresh-1"


@pytest.mark.parametrize("changes", [{"client_id": CLIENT}, {"scope": "aws.cognito.signin.user.admin"},
                                      {"scope": "team5-web/analysis aws.cognito.signin.user.admin"}, {"sub": "wrong"}])
def test_native_access_wrong_client_scope_or_sub_is_rejected(changes):
    api = NativeApi(); api.bind()
    # Replace only the provider fixture result, preserving the real validator.
    original = api.native.authenticate
    def changed(*args):
        result = original(*args)
        result["access_token"] = jwt(api.clock[0], **{"client_id": LOGIN, "scope": "team5-web/analysis", **changes})
        return result
    api.native.authenticate = changed
    assert api.signin()[0]["statusCode"] == 503
    assert not any(k.startswith("SESSION#") for k in api.store.rows)


def test_native_refresh_subject_changed_expires_without_replay():
    api = NativeApi(); api.bind(); api.signin(); api.clock[0] += 241
    original = api.native.refresh
    def changed(*args):
        result = original(*args)
        result["access_token"] = jwt(api.clock[0], client_id=LOGIN, scope="team5-web/analysis", sub="changed-sub")
        result["id_token"] = id_token(api.clock[0], sub="changed-sub")
        return result
    api.native.refresh = changed
    assert api.call("/api/auth/session")[0]["statusCode"] == 401
    assert api.call("/api/auth/session")[1] == {"authenticated": False}
    assert len(api.cognito.calls) == 2 and len(api.cognito.revoked) == 1


def test_ambiguous_final_commit_never_returns_token_or_retries_credentials():
    api = NativeApi(); api.bind()
    commit = api.store.commit
    def ambiguous(changes, checks=()):
        commit(changes, checks)
        if any(row["pk"].startswith("SESSION#") for row, _ in changes):
            raise TimeoutError("response lost after durable transaction")
    api.store.commit = ambiguous
    response, value = api.signin()
    assert response["statusCode"] == 503 and "access_token" not in value
    assert "multiValueHeaders" not in response
    assert len(api.cognito.calls) == 1 and len(api.cognito.revoked) == 1
    assert api.call("/api/auth/session")[1] == {"authenticated": False}
    assert len(api.cognito.calls) == 1


def test_stored_wrong_native_client_fails_before_cached_token_or_refresh():
    api = NativeApi(); api.bind(); api.signin()
    row = api.store.rows[key("SESSION", api.cookies[SESSION_COOKIE])]
    row["provider_client_id"] = SIGNUP
    response, value = api.call("/api/auth/session")
    assert response["statusCode"] == 503 and "access_token" not in value
    assert len(api.cognito.calls) == 1


def test_new_oauth_attempt_supersedes_pending_native_without_destroying_legacy_session():
    api = NativeApi(); old = api.login()
    api.cognito.on_auth = lambda: api.start()
    response, value = api.signin()
    assert response["statusCode"] == 409 and value["code"] == "signin_cancelled"
    assert api.call("/api/auth/session")[1]["session_ref"] == old["session_ref"]
    assert len(api.cognito.revoked) == 1


def test_native_sdk_parameter_shapes_with_actual_botocore_stubber():
    import boto3
    from botocore.stub import Stubber
    client = boto3.client("cognito-idp", region_name=REGION, aws_access_key_id="fixture", aws_secret_access_key="fixture")
    native = CognitoNative(client, LOGIN, SECRET, signup_client_id=SIGNUP)
    tokens = {"AccessToken": "fixture-access", "IdToken": "fixture-id", "RefreshToken": "fixture-refresh",
              "ExpiresIn": 300, "TokenType": "Bearer"}
    with Stubber(client) as stub:
        stub.add_response("initiate_auth", {"AuthenticationResult": tokens}, {
            "ClientId": LOGIN, "AuthFlow": "USER_PASSWORD_AUTH", "AuthParameters": {
                "USERNAME": EMAIL, "PASSWORD": "supplied-password", "SECRET_HASH": native.secret_hash(EMAIL)}})
        stub.add_response("initiate_auth", {"AuthenticationResult": {k: v for k, v in tokens.items() if k != "RefreshToken"}}, {
            "ClientId": LOGIN, "AuthFlow": "REFRESH_TOKEN_AUTH", "AuthParameters": {
                "REFRESH_TOKEN": "fixture-refresh", "SECRET_HASH": native.secret_hash(SUB)}})
        stub.add_response("revoke_token", {}, {"ClientId": LOGIN, "ClientSecret": SECRET, "Token": "fixture-refresh"})
        assert native.authenticate(EMAIL, "supplied-password")["access_token"] == "fixture-access"
        assert native.refresh("fixture-refresh", SUB)["refresh_token"] is None
        native.revoke("fixture-refresh")
        stub.assert_no_pending_responses()


def test_legacy_untyped_session_uses_legacy_refresh_and_revoke():
    api = NativeApi(); api.login()
    pk = key("SESSION", api.cookies[SESSION_COOKIE]); row = api.store.rows[pk]
    row.pop("provider_kind"); row.pop("provider_client_id")
    api.clock[0] += 3550
    assert api.call("/api/auth/session")[0]["statusCode"] == 200
    response, value = api.call("/api/auth/logout", "POST")
    assert response["statusCode"] == 200 and value["logged_out"] is True
    assert not api.cognito.calls and not api.cognito.revoked
    assert [c[0] for c in api.provider.calls].count("refresh") == 1
    assert [c[0] for c in api.provider.calls].count("revoke") == 1


def test_replace_oauth_then_native_sessions_revoke_their_own_provider():
    api = NativeApi(); api.login(); api.signin()
    assert api.provider.calls[-1] == ("revoke", "server-refresh") and not api.cognito.revoked
    api.login()
    assert api.cognito.revoked[-1]["ClientId"] == LOGIN
    assert api.cognito.revoked[-1]["Token"] == "native-refresh-1"


@pytest.mark.parametrize("final_window", [False, True])
def test_logout_fences_pending_native_login_even_at_final_commit(final_window):
    api = NativeApi(); api.bind()
    if final_window:
        def on_auth():
            api.store.hook = lambda changes, checks: api.call("/api/auth/logout", "POST")
        api.cognito.on_auth = on_auth
    else:
        api.cognito.on_auth = lambda: api.call("/api/auth/logout", "POST")
    response, value = api.signin()
    assert response["statusCode"] == 409 and value["code"] == "signin_cancelled"
    assert not any(k.startswith("SESSION#") for k in api.store.rows)
    assert len(api.cognito.revoked) == 1


def test_refresh_logout_fences_native_and_revoke_uses_native_client():
    api = NativeApi(); api.bind(); api.signin(); api.clock[0] += 241
    api.cognito.on_auth = lambda: api.call("/api/auth/logout", "POST")
    assert api.call("/api/auth/session")[0]["statusCode"] == 401
    assert all(v["ClientId"] == LOGIN for v in api.cognito.revoked)
    assert not any(c[0] == "revoke" for c in api.provider.calls)
    assert api.call("/api/auth/session")[1] == {"authenticated": False}


def test_rate_limit_before_provider_and_counter_contains_no_clear_identity():
    api = NativeApi(); api.bind(); api.cognito.error = CognitoError("NotAuthorizedException")
    for _ in range(5):
        assert api.signin()[0]["statusCode"] == 401
    response, value = api.signin()
    assert response["statusCode"] == 429 and type(value["retry_after_seconds"]) is int
    assert len(api.cognito.calls) == 5
    assert EMAIL not in json.dumps(api.store.rows) and "203.0.113.20" not in json.dumps(api.store.rows)
    api = NativeApi(); api.bind(); api.cognito.error = CognitoError("NotAuthorizedException")
    for n in range(30):
        assert api.signin(email=f"user{n}@example.com")[0]["statusCode"] == 401
    assert api.signin(email="another@example.com")[0]["statusCode"] == 429
    assert len(api.cognito.calls) == 30


def trigger(**changes):
    return {"version": "2", "region": REGION, "userPoolId": POOL, "triggerSource": "TokenGeneration_Authentication",
            "callerContext": {"clientId": LOGIN}, "request": {"userAttributes": {
                "sub": SUB, "email": EMAIL, "email_verified": "true"}, "scopes": ["aws.cognito.signin.user.admin"]},
            "response": {}, **changes}


@pytest.mark.parametrize("source", ["TokenGeneration_Authentication", "TokenGeneration_RefreshTokens"])
def test_exact_native_trigger_grants_analysis_and_removes_user_admin(source):
    event = trigger(triggerSource=source); original = deepcopy(event)
    result = customize(event, login_client_id=LOGIN, signup_client_id=SIGNUP)
    assert event == original
    assert result["response"] == {"claimsAndScopeOverrideDetails": {"accessTokenGeneration": {
        "scopesToAdd": ["team5-web/analysis"], "scopesToSuppress": ["aws.cognito.signin.user.admin"]}}}


@pytest.mark.parametrize("client", [CLIENT, SIGNUP, "unrelated-client"])
def test_other_client_tokens_are_returned_identically_with_no_analysis_scope(client):
    event = trigger(callerContext={"clientId": client}, version="1", response={"existing": "unchanged"})
    assert customize(event, login_client_id=LOGIN, signup_client_id=SIGNUP) is event
    assert event["response"] == {"existing": "unchanged"}


@pytest.mark.parametrize("change", [{"version": "1"}, {"version": "3"}, {"region": "us-east-1"},
                                   {"userPoolId": "wrong"}, {"triggerSource": "TokenGeneration_HostedAuth"},
                                   {"triggerSource": "TokenGeneration_NewPasswordChallenge"}])
def test_exact_client_invalid_trigger_source_fails_closed(change):
    with pytest.raises(ValueError, match="login_token_request_rejected"):
        customize(trigger(**change), login_client_id=LOGIN, signup_client_id=SIGNUP)


@pytest.mark.parametrize("attributes", [{"sub": SUB, "email": EMAIL, "email_verified": "false"},
                                       {"sub": "", "email": EMAIL, "email_verified": "true"},
                                       {"sub": SUB, "email": None, "email_verified": "true"}])
def test_trigger_requires_verified_email_and_sub(attributes):
    with pytest.raises(ValueError, match="login_token_request_rejected"):
        customize(trigger(request={"userAttributes": attributes}), login_client_id=LOGIN, signup_client_id=SIGNUP)


@pytest.mark.parametrize("client", [CLIENT, SIGNUP, None])
def test_public_or_signup_client_cannot_be_configured_as_login_client(client):
    with pytest.raises(ValueError):
        CognitoNative(None, client, SECRET, signup_client_id=SIGNUP)
    with pytest.raises(ValueError):
        customize(trigger(), login_client_id=client, signup_client_id=SIGNUP)
