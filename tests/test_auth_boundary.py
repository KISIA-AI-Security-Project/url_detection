from copy import deepcopy
import base64
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from web_service.auth_sessions import Conflict, AuthError, DynamoAuthStore, key, next_row, password
from web_service.auth_service import (AuthService, BROWSER_COOKIE, SESSION_COOKIE, CLIENT, ISSUER,
    ORIGIN, CognitoOAuth, ProviderError, provider_tokens)
from web_service.auth_signup import SignupService, CognitoSignup


class Store:
    def __init__(self):
        self.rows = {}
        self.hook = None

    def read(self, pk):
        return deepcopy(self.rows.get(pk))

    def commit(self, changes, checks=()):
        if self.hook:
            hook, self.hook = self.hook, None
            hook(changes, checks)
        for pk, version in [(x[0]["pk"], x[1]) for x in changes] + list(checks):
            actual = self.rows.get(pk)
            if version is None and actual is not None or version is not None and (actual is None or actual["version"] != version):
                raise Conflict()
        for row, _ in changes:
            self.rows[row["pk"]] = deepcopy(row)


def jwt(now, **changes):
    claims = {"iss": ISSUER, "client_id": CLIENT, "token_use": "access", "scope": "openid email team5-web/analysis",
              "sub": "01234567-0123-0123-0123-012345678901", "exp": now + 3600, **changes}
    def enc(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")
    return enc({"alg": "RS256", "kid": "mock-provider-only"}) + "." + enc(claims) + ".mock"


class OAuth:
    def __init__(self, clock):
        self.clock = clock
        self.calls = []
        self.on_exchange = None
        self.on_refresh = None
        self.bad_claims = {}
        self.refresh_error = False

    def tokens(self):
        return {"access_token": jwt(self.clock[0], **self.bad_claims), "refresh_token": "server-refresh", "expires_in": 3600}

    def exchange(self, code, verifier):
        self.calls.append(("exchange", code, verifier))
        if self.on_exchange:
            self.on_exchange()
        return self.tokens()

    def refresh(self, token):
        self.calls.append(("refresh", token))
        if self.on_refresh:
            self.on_refresh()
        if self.refresh_error:
            raise ProviderError()
        return self.tokens()

    def revoke(self, token):
        self.calls.append(("revoke", token))


class Api:
    def __init__(self):
        self.clock = [2000000000]
        self.store = Store()
        self.provider = OAuth(self.clock)
        self.app = AuthService(self.store, self.provider, clock=lambda: self.clock[0])
        self.cookies = {}

    def call(self, path, method="GET", body=None, headers=None, cookies=None):
        event = {"path": path, "httpMethod": method, "requestContext": {"identity": {"sourceIp": "203.0.113.20"}}, "headers": {
            "origin": ORIGIN, "content-type": "application/json", "x-linkguard-request": "v1",
            "cookie": "; ".join(k + "=" + v for k, v in (self.cookies if cookies is None else cookies).items()), **(headers or {})},
            "body": json.dumps(body or {})}
        result = self.app.handle(event)
        for line in result.get("multiValueHeaders", {}).get("Set-Cookie", []):
            name, value = line.split(";", 1)[0].split("=", 1)
            if value:
                self.cookies[name] = value
            else:
                self.cookies.pop(name, None)
        return result, json.loads(result["body"])

    def start(self):
        result, _ = self.call("/api/auth/login")
        assert result["statusCode"] == 302
        return parse_qs(urlsplit(result["headers"]["location"]).query)["state"][0]

    def login(self):
        state = self.start()
        result, value = self.call("/api/auth/callback", "POST", {"code": "provider-code", "state": state})
        assert result["statusCode"] == 200
        return value


def test_opaque_http_only_session_reload_and_ref_lifecycle():
    api = Api()
    result, value = api.call("/api/auth/session")
    assert value == {"authenticated": False}
    assert "no-store" in result["headers"]["cache-control"]
    assert "multiValueHeaders" not in result and not api.store.rows
    result, _ = api.call("/api/auth/login")
    line = result["multiValueHeaders"]["Set-Cookie"][0]
    assert all(x in line for x in ("__Host-", "Path=/", "Secure", "HttpOnly", "SameSite=Lax"))
    assert "Domain=" not in line
    accepted = api.login()
    cookie_value = api.cookies[SESSION_COOKIE]
    assert cookie_value != accepted["session_ref"] and "." not in cookie_value
    assert set(accepted) == {"authenticated", "access_token", "expires_at", "session_ref"}
    _, restored = api.call("/api/auth/session")
    assert restored == accepted
    api.clock[0] += 3550
    _, refreshed = api.call("/api/auth/session")
    assert refreshed["session_ref"] == accepted["session_ref"]
    again = api.login()
    assert again["session_ref"] != accepted["session_ref"]


@pytest.mark.parametrize("headers", [{"origin": "https://attacker.invalid"}, {"x-linkguard-request": ""}, {"content-type": "text/plain"}])
def test_csrf_precedes_all_mutations(headers):
    api = Api()
    result, _ = api.call("/api/auth/callback", "POST", {"code": "x", "state": "x"}, headers)
    assert result["statusCode"] == 403
    assert not api.store.rows and not api.provider.calls


@pytest.mark.parametrize("change", [{"scope": "aws.cognito.signin.user.admin"}, {"client_id": "wrong"}, {"iss": "https://attacker.invalid"}, {"token_use": "id"}, {"exp": 1}, {"sub": None}])
def test_fixed_provider_claim_checks_do_not_mint_session(change):
    api = Api()
    api.provider.bad_claims = change
    state = api.start()
    result, value = api.call("/api/auth/callback", "POST", {"code": "x", "state": state})
    assert result["statusCode"] == 503 and "access_token" not in value
    assert not any(k.startswith("SESSION#") for k in api.store.rows)
    assert any(c[0] == "revoke" for c in api.provider.calls)


def test_callback_state_wrong_browser_replay_and_expired():
    api = Api()
    state = api.start()
    saved = deepcopy(api.cookies)
    result, _ = api.call("/api/auth/callback", "POST", {"code": "x", "state": state}, cookies={})
    assert result["statusCode"] == 401
    result, _ = api.call("/api/auth/callback", "POST", {"code": "x", "state": state}, cookies=saved)
    assert result["statusCode"] == 200
    result, _ = api.call("/api/auth/callback", "POST", {"code": "x", "state": state})
    assert result["statusCode"] == 409
    state = api.start()
    api.clock[0] += 601
    result, _ = api.call("/api/auth/callback", "POST", {"code": "x", "state": state})
    assert result["statusCode"] == 409
    assert sum(c[0] == "exchange" for c in api.provider.calls) == 1


def test_pending_callback_logout_never_creates_session():
    api = Api()
    state = api.start()
    api.provider.on_exchange = lambda: api.call("/api/auth/logout", "POST")
    result, value = api.call("/api/auth/callback", "POST", {"code": "x", "state": state})
    assert result["statusCode"] == 409 and "access_token" not in value
    assert not any(k.startswith("SESSION#") for k in api.store.rows)
    assert any(c[0] == "revoke" for c in api.provider.calls)


def test_logout_in_final_transaction_window_cannot_recreate_session():
    api = Api()
    state = api.start()
    def exchange_hook():
        def before_commit(changes, checks):
            assert any(row["pk"].startswith("SESSION#") for row, _ in changes)
            api.call("/api/auth/logout", "POST")
        api.store.hook = before_commit
    api.provider.on_exchange = exchange_hook
    result, _ = api.call("/api/auth/callback", "POST", {"code": "x", "state": state})
    assert result["statusCode"] == 409
    assert not any(k.startswith("SESSION#") for k in api.store.rows)


def test_refresh_logout_race_and_no_cookie_session_resurrection():
    api = Api()
    api.login()
    api.clock[0] += 3550
    api.provider.on_refresh = lambda: api.call("/api/auth/logout", "POST")
    result, value = api.call("/api/auth/session")
    assert result["statusCode"] == 401 and "access_token" not in value
    sessions = [v for k, v in api.store.rows.items() if k.startswith("SESSION#")]
    assert all(x["status"] == "revoked" and "refresh_token" not in x for x in sessions)


def test_parallel_refresh_409_and_unknown_refresh_never_replayed():
    api = Api()
    api.login()
    api.clock[0] += 3550
    captured = []
    api.provider.on_refresh = lambda: captured.append(api.call("/api/auth/session"))
    api.provider.refresh_error = True
    result, _ = api.call("/api/auth/session")
    assert result["statusCode"] == 401
    assert captured[0][0]["statusCode"] == 409 and captured[0][1]["code"] == "session_refreshing"
    _, value = api.call("/api/auth/session")
    assert value == {"authenticated": False}
    assert sum(c[0] == "refresh" for c in api.provider.calls) == 1


def test_expired_dynamo_row_is_not_an_authenticated_session():
    api = Api()
    api.login()
    api.clock[0] += 86401
    _, value = api.call("/api/auth/session")
    assert value == {"authenticated": False}


def test_late_unauthenticated_session_get_cannot_clear_new_session_cookie():
    api = Api()
    api.call("/api/auth/session")
    result, value = api.call("/api/auth/session")
    assert value == {"authenticated": False}
    assert not any(line.startswith(SESSION_COOKIE + "=") for line in result.get("multiValueHeaders", {}).get("Set-Cookie", []))
    api.login()
    api.clock[0] += 3550
    api.provider.refresh_error = True
    result, _ = api.call("/api/auth/session")
    assert not any(line.startswith(SESSION_COOKIE + "=") for line in result.get("multiValueHeaders", {}).get("Set-Cookie", []))


def test_new_login_lifetime_starts_after_long_anonymous_page_wait():
    api = Api()
    api.call("/api/auth/session")
    api.clock[0] += 80000
    api.login()
    row = api.store.read(key("SESSION", api.cookies[SESSION_COOKIE]))
    assert row["expires_at"] == api.clock[0] + 86340


def test_signup_revoke_failure_does_not_repeat_password_change():
    api = SignupApi()
    api.verified_signup()
    api.signup_provider.revoke = lambda token: (_ for _ in ()).throw(TimeoutError())
    result, value = api.signup_call("complete", password="abcdefgh!")
    assert result["statusCode"] == 200 and value["status"] == "complete"
    row = next(v for k, v in api.store.rows.items() if k.startswith("SIGNUP#"))
    assert row["revoke_status"] == "unknown" and "placeholder" not in row
    api.signup_call("complete", password="otherpass!")
    assert sum(x[0] == "change" for x in api.signup_provider.calls) == 1


class CognitoError(Exception):
    def __init__(self, code):
        self.response = {"Error": {"Code": code}}


class SignupProvider:
    def __init__(self):
        self.calls = []
        self.sub = "new-user-sub"
        self.email = "new@example.com"
        self.verified = "true"
        self.start_error = None
        self.confirm_error = None
        self.change_error = None
        self.changed_password = False
        self.authentication_challenge = False
        self.hook_change = None

    def start(self, email, placeholder):
        self.calls.append(("start", email, placeholder))
        if self.start_error:
            raise self.start_error
        return {"UserSub": self.sub, "UserConfirmed": False, "CodeDeliveryDetails": {"Destination": "n***@e***", "DeliveryMedium": "EMAIL"}}

    def resend(self, email):
        self.calls.append(("resend", email))
        return {"CodeDeliveryDetails": {"Destination": "n***@e***", "DeliveryMedium": "EMAIL"}}

    def confirm(self, email, code):
        self.calls.append(("confirm", email, code))
        if self.confirm_error:
            raise self.confirm_error

    def authenticate(self, email, placeholder):
        self.calls.append(("authenticate", email, placeholder))
        if self.changed_password:
            raise CognitoError("NotAuthorizedException")
        if self.authentication_challenge:
            return {"ChallengeName": "NEW_PASSWORD_REQUIRED"}
        return {"AuthenticationResult": {"AccessToken": "private-access", "RefreshToken": "private-refresh"}}

    def user(self, token):
        self.calls.append(("user", token))
        return {"UserAttributes": [{"Name": "sub", "Value": self.sub}, {"Name": "email", "Value": self.email}, {"Name": "email_verified", "Value": self.verified}]}

    def change(self, token, old, new):
        self.calls.append(("change", token, old, new))
        if self.hook_change:
            self.hook_change()
        if self.change_error:
            raise self.change_error

    def revoke(self, token):
        self.calls.append(("revoke", token))


class SignupApi(Api):
    def __init__(self):
        super().__init__()
        self.signup_provider = SignupProvider()
        self.app.signup = SignupService(self.store, self.signup_provider)
        self.intent = "test-intent-1234567890123456"
        self.call("/api/auth/session")

    def signup_call(self, action, **fields):
        return self.call("/api/auth/signup/" + action, "POST", {"intent_id": self.intent, **fields})

    def verified_signup(self):
        result, value = self.signup_call("start", email="New@Example.COM")
        assert result["statusCode"] == 200 and value["email"] == "new@example.com"
        result, value = self.signup_call("confirm", code="123456")
        assert result["statusCode"] == 200 and value["status"] == "verified"


def test_email_first_same_intent_once_only_provider_password_and_no_browser_credentials():
    api = SignupApi()
    api.verified_signup()
    original_cookie = api.cookies[BROWSER_COOKIE]
    result, value = api.signup_call("start", email="new@example.com")
    assert value["status"] == "verified"
    result, value = api.signup_call("complete", password="abcdefgh!")
    assert value == {"intent_id": api.intent, "status": "complete", "login_required": True}
    result2, value2 = api.signup_call("complete", password="anotherpass!")
    assert value2 == value
    names = [x[0] for x in api.signup_provider.calls]
    assert names == ["start", "confirm", "authenticate", "user", "change", "revoke"]
    assert api.cookies == {BROWSER_COOKIE: original_cookie}
    assert not any("placeholder" in r for k, r in api.store.rows.items() if k.startswith("SIGNUP#"))
    assert "private" not in json.dumps(value)


@pytest.mark.parametrize("failure", [CognitoError("UsernameExistsException"), CognitoError("LimitExceededException"), TimeoutError()])
def test_signup_existing_or_unknown_is_never_adopted(failure):
    api = SignupApi()
    api.signup_provider.start_error = failure
    first, _ = api.signup_call("start", email="new@example.com")
    assert first["statusCode"] == 409
    api.signup_call("start", email="new@example.com")
    api.signup_call("confirm", code="123456")
    api.signup_call("complete", password="abcdefgh!")
    assert [x[0] for x in api.signup_provider.calls] == ["start"]


def test_signup_email_intent_binding_expiry_and_no_cookie_replacement():
    api = SignupApi()
    result, _ = api.signup_call("start", email="new@example.com")
    assert result["multiValueHeaders"]["Set-Cookie"][0].startswith(BROWSER_COOKIE + "=")
    result, _ = api.signup_call("start", email="new@example.com")
    assert "multiValueHeaders" not in result
    result, _ = api.signup_call("start", email="other@example.com")
    assert result["statusCode"] == 409
    original = deepcopy(api.cookies)
    api.cookies = {}
    api.call("/api/auth/session")
    result, _ = api.signup_call("confirm", code="123456")
    assert result["statusCode"] == 401
    api.cookies = original
    api.clock[0] += 601
    result, _ = api.signup_call("confirm", code="123456")
    assert result["statusCode"] == 410
    assert len(api.signup_provider.calls) == 1


def test_resend_cooldown_and_confirm_failures_count_before_provider():
    api = SignupApi()
    api.signup_call("start", email="new@example.com")
    result, _ = api.signup_call("resend")
    assert result["statusCode"] == 429
    api.clock[0] += 61
    result, _ = api.signup_call("resend")
    assert result["statusCode"] == 200
    api.signup_provider.confirm_error = CognitoError("CodeMismatchException")
    for _ in range(5):
        result, value = api.signup_call("confirm", code="123456")
        assert result["statusCode"] == 400 and value["code"] == "code_mismatch"
    result, _ = api.signup_call("confirm", code="123456")
    assert result["statusCode"] == 429
    assert sum(x[0] == "confirm" for x in api.signup_provider.calls) == 5


def test_confirm_timeout_not_promoted_to_verified_or_retried():
    api = SignupApi()
    api.signup_call("start", email="new@example.com")
    api.signup_provider.confirm_error = TimeoutError()
    result, value = api.signup_call("confirm", code="123456")
    assert result["statusCode"] == 409 and value["code"] == "verification_unknown"
    api.signup_call("confirm", code="123456")
    api.signup_call("complete", password="abcdefgh!")
    assert sum(x[0] == "confirm" for x in api.signup_provider.calls) == 1
    assert not any(x[0] == "change" for x in api.signup_provider.calls)


@pytest.mark.parametrize("field,value", [("sub", "different-sub"), ("email", "other@example.com"), ("verified", "false"), ("changed_password", True), ("authentication_challenge", True)])
def test_provider_identity_or_current_placeholder_mismatch_cannot_change_password(field, value):
    api = SignupApi()
    api.verified_signup()
    setattr(api.signup_provider, field, value)
    result, value = api.signup_call("complete", password="abcdefgh!")
    assert result["statusCode"] == 409
    assert not any(x[0] == "change" for x in api.signup_provider.calls)


def test_change_password_unknown_and_concurrent_complete_never_reissue():
    api = SignupApi()
    api.verified_signup()
    captured = []
    api.signup_provider.hook_change = lambda: captured.append(api.signup_call("complete", password="otherpass!"))
    api.signup_provider.change_error = TimeoutError()
    result, value = api.signup_call("complete", password="abcdefgh!")
    assert result["statusCode"] == 409 and value["code"] == "completion_unknown"
    assert captured[0][0]["statusCode"] == 409
    api.signup_call("complete", password="otherpass!")
    assert sum(x[0] == "change" for x in api.signup_provider.calls) == 1


def test_successful_password_change_then_store_failure_stays_unknown():
    api = SignupApi()
    api.verified_signup()
    def fail_after_provider():
        api.store.hook = lambda changes, checks: (_ for _ in ()).throw(RuntimeError("simulated write failure"))
    api.signup_provider.hook_change = fail_after_provider
    result, value = api.signup_call("complete", password="abcdefgh!")
    assert result["statusCode"] == 409 and value["code"] == "completion_unknown"
    api.signup_call("complete", password="abcdefgh!")
    assert sum(x[0] == "change" for x in api.signup_provider.calls) == 1


@pytest.mark.parametrize("value", ["short!", "abcdefgh", "abcdefgh! ", "abcd efgh!", "abcd\tefgh!", "abcde\u00a0fgh!"])
def test_password_policy(value):
    with pytest.raises(AuthError):
        password(value)


def test_real_dynamodb_serializer_accepts_all_records_and_condition_writes():
    from boto3.dynamodb.types import TypeSerializer
    api = SignupApi()
    api.verified_signup()
    api.login()
    serializer = TypeSerializer()
    for row in api.store.rows.values():
        serializer.serialize(row)
        assert isinstance(row["expires_at"], int)
    class Client:
        def __init__(self):
            self.calls = []
        def transact_write_items(self, **kwargs):
            self.calls.append(kwargs)
    client = Client()
    store = DynamoAuthStore(client, "test-table")
    row = next(iter(api.store.rows.values()))
    store.commit([(next_row(row, status="revoked"), row["version"])], [("OTHER", 2)])
    tx = client.calls[0]["TransactItems"]
    assert tx[0]["Put"]["ConditionExpression"] == "#v = :v"
    assert tx[1]["ConditionCheck"]["ExpressionAttributeValues"] == {":v": {"N": "2"}}


def test_cognito_adapter_never_uses_admin_apis_or_public_oauth_client():
    class Client:
        def __init__(self):
            self.calls = []
        def __getattr__(self, name):
            def call(**kwargs):
                self.calls.append((name, kwargs))
                return {}
            return call
    client = Client()
    adapter = CognitoSignup(client, "private-client", "x" * 32)
    adapter.start("new@example.com", "server-placeholder")
    adapter.confirm("new@example.com", "123456")
    adapter.authenticate("new@example.com", "server-placeholder")
    adapter.user("private-access")
    adapter.change("private-access", "server-placeholder", "user-password!")
    adapter.revoke("private-refresh")
    assert [x[0] for x in client.calls] == ["sign_up", "confirm_sign_up", "initiate_auth", "get_user", "change_password", "revoke_token"]
    assert client.calls[1][1]["ForceAliasCreation"] is False
    assert client.calls[2][1]["AuthParameters"]["SECRET_HASH"] == adapter.secret_hash("new@example.com")
    with pytest.raises(ValueError):
        CognitoSignup(client, CLIENT, "x" * 32)
