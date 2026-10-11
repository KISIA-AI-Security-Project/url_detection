"""Same-origin OAuth session boundary; existing analysis Bearer APIs are unchanged.

Provider tokens enter only through our fixed Cognito HTTPS token endpoint, never
from browser-supplied JWTs. Claims are checked here; the existing API Gateway
authorizer still validates JWT signatures for every analysis/SSE request.
"""
from __future__ import annotations
import base64
import json
import os
import re
import time
from urllib.parse import urlencode
from urllib.request import Request, build_opener, HTTPRedirectHandler
from urllib.error import HTTPError

from .auth_sessions import (AuthError, Conflict, DynamoAuthStore, digest, email_address,
    expired, key, next_row, opaque, public_error, redact_session)

ORIGIN = "https://d2gmygchoew9ed.cloudfront.net"
DOMAIN = "https://team5-web-20261006-998301375101.auth.ap-northeast-2.amazoncognito.com"
CLIENT = "11v9bek84i6fakpvhtk5nk4sth"
POOL = "ap-northeast-2_dlm4zCq7C"
ISSUER = "https://cognito-idp.ap-northeast-2.amazonaws.com/" + POOL
SCOPE = "openid email team5-web/analysis"
BROWSER_COOKIE = "__Host-linkguard_browser"
SESSION_COOKIE = "__Host-linkguard_session"
TOKEN_PATTERN = re.compile(r"^[A-Za-z0-9_-]{43}$")


class ProviderError(Exception):
    def __init__(self, definitive=False):
        self.definitive = definitive


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        # A fixed trusted token endpoint must never forward credentials elsewhere.
        return None


class CognitoOAuth:
    def request(self, path, values):
        request = Request(DOMAIN + path, data=urlencode(values).encode("ascii"), method="POST",
                          headers={"content-type": "application/x-www-form-urlencoded"})
        try:
            with build_opener(NoRedirect()).open(request, timeout=10) as response:
                data = response.read(65537)
                if len(data) > 65536:
                    raise ProviderError()
                return json.loads(data) if data else {}
        except HTTPError as error:
            # Never include a provider response/body or submitted secrets in logs.
            raise ProviderError(error.code in (400, 401)) from None
        except ProviderError:
            raise
        except Exception:
            raise ProviderError() from None

    def exchange(self, code, verifier):
        return self.request("/oauth2/token", {"grant_type": "authorization_code", "client_id": CLIENT,
            "code": code, "code_verifier": verifier, "redirect_uri": ORIGIN + "/"})

    def refresh(self, token):
        return self.request("/oauth2/token", {"grant_type": "refresh_token", "client_id": CLIENT,
            "refresh_token": token})

    def revoke(self, token):
        return self.request("/oauth2/revoke", {"client_id": CLIENT, "token": token})


def cookie(name, value, max_age):
    return f"{name}={value}; Path=/; Max-Age={max(0, int(max_age))}; Secure; HttpOnly; SameSite=Lax"


def parse_cookies(event):
    headers = event.get("headers") or {}
    raw = next((v for k, v in headers.items() if k.lower() == "cookie"), "")
    result = {}
    for pair in raw.split(";"):
        name, separator, value = pair.strip().partition("=")
        if separator and name in (BROWSER_COOKIE, SESSION_COOKIE):
            if name in result or not TOKEN_PATTERN.fullmatch(value):
                raise AuthError(401, "authentication_required", "로그인을 다시 시작해 주세요.")
            result[name] = value
    return result


def response(status, value, cookies=(), location=None):
    headers = {"content-type": "application/json; charset=utf-8", "cache-control": "no-store, private",
               "pragma": "no-cache", "x-content-type-options": "nosniff", "referrer-policy": "no-referrer"}
    if location:
        headers["location"] = location
    if isinstance(value, dict) and value.get("retry_after_seconds") is not None:
        headers["retry-after"] = str(value["retry_after_seconds"])
    result = {"statusCode": status, "headers": headers, "body": json.dumps(value, ensure_ascii=False)}
    if cookies:
        result["multiValueHeaders"] = {"Set-Cookie": list(cookies)}
    return result


def post_body(event):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    if headers.get("origin") != ORIGIN or headers.get("x-linkguard-request") != "v1" or headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise AuthError(403, "request_origin_invalid", "서비스 화면에서 다시 요청해 주세요.")
    raw = event.get("body") or "{}"
    try:
        if event.get("isBase64Encoded"):
            raw = base64.b64decode(raw, validate=True).decode("utf-8")
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > 16384:
            raise ValueError()
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, TypeError, UnicodeError):
        raise AuthError(400, "bad_request", "요청 형식을 확인해 주세요.") from None


def provider_tokens(value, now, fallback_refresh=None, expected_sub=None, *, expected_client=CLIENT):
    try:
        token = value["access_token"]
        if not isinstance(token, str) or len(token) > 16384:
            raise ValueError()
        pieces = token.split(".")
        if len(pieces) != 3:
            raise ValueError()
        header = json.loads(base64.urlsafe_b64decode(pieces[0] + "=" * (-len(pieces[0]) % 4)))
        claims = json.loads(base64.urlsafe_b64decode(pieces[1] + "=" * (-len(pieces[1]) % 4)))
        if header.get("alg") != "RS256" or not header.get("kid") or claims.get("iss") != ISSUER or claims.get("client_id") != expected_client or claims.get("token_use") != "access" or "team5-web/analysis" not in claims.get("scope", "").split():
            raise ValueError()
        sub = claims.get("sub")
        if not isinstance(sub, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", sub) or (expected_sub and sub != expected_sub):
            raise ValueError()
        if type(claims.get("exp")) is not int or type(value.get("expires_in")) is not int or value["expires_in"] <= 0:
            raise ValueError()
        expiration = min(claims["exp"], now + value["expires_in"])
        refresh = value.get("refresh_token") or fallback_refresh
        if expiration <= now + 5 or not isinstance(refresh, str) or not refresh or len(refresh) > 16384:
            raise ValueError()
        return {"access_token": token, "refresh_token": refresh, "access_expires_at": expiration, "sub": sub}
    except Exception:
        raise ProviderError() from None


class AuthService:
    def __init__(self, store, provider, *, clock=time.time, random=opaque, signup=None, native=None):
        self.store, self.provider, self.clock, self.random, self.signup = store, provider, clock, random, signup
        self.native = native

    def browser(self, cookies, now, outgoing, create=False):
        value = cookies.get(BROWSER_COOKIE)
        row = self.store.read(key("BROWSER", value)) if value else None
        if row and not expired(row, now) and row["status"] == "active":
            return row
        if not create:
            raise AuthError(401, "authentication_required", "로그인을 다시 시작해 주세요.")
        value = self.random()
        row = {"pk": key("BROWSER", value), "version": 0, "status": "active", "expires_at": now + 86400, "ttl": now + 90000}
        self.store.commit([(row, None)])
        outgoing.append(cookie(BROWSER_COOKIE, value, 86400))
        return row

    def active_browser(self, browser, now):
        current = self.store.read(browser["pk"])
        if expired(current, now) or current["status"] != "active":
            raise AuthError(401, "authentication_required", "로그인을 다시 시작해 주세요.")
        return current

    def session_provider(self, row):
        kind = row.get("provider_kind", "oauth")
        client = row.get("provider_client_id", CLIENT)
        if kind == "oauth" and client == CLIENT:
            return self.provider
        if kind == "native" and self.native is not None and client == self.native.client_id:
            return self.native
        raise ProviderError()

    def revoke_best_effort(self, token, row=None):
        if token:
            try:
                self.session_provider(row or {}).revoke(token)
            except Exception:
                return False
        return True

    def login(self, browser, query, now):
        hint = email_address(query["login_hint"]) if query.get("login_hint") else None
        state, verifier = self.random(), self.random()
        tx = {"pk": key("OAUTH", state), "version": 0, "status": "pending", "browser_pk": browser["pk"],
              "verifier": verifier, "expires_at": now + 600, "ttl": now + 3600}
        updated = next_row(browser, oauth_tx=tx["pk"], expires_at=now + 86400, ttl=now + 90000)
        self.store.commit([(updated, browser["version"]), (tx, None)])
        challenge = base64.urlsafe_b64encode(__import__("hashlib").sha256(verifier.encode()).digest()).decode().rstrip("=")
        values = {"client_id": CLIENT, "response_type": "code", "scope": SCOPE, "redirect_uri": ORIGIN + "/",
                  "state": state, "code_challenge": challenge, "code_challenge_method": "S256"}
        if hint:
            values["login_hint"] = hint
        return DOMAIN + "/oauth2/authorize?" + urlencode(values)

    def callback(self, browser, body, now, outgoing):
        if set(body) != {"code", "state"} or not isinstance(body["state"], str) or not TOKEN_PATTERN.fullmatch(body["state"]) or not isinstance(body["code"], str) or not 1 <= len(body["code"]) <= 2048:
            raise AuthError(400, "bad_request", "로그인 응답을 확인해 주세요.")
        tx = self.store.read(key("OAUTH", body["state"]))
        if expired(tx, now) or tx.get("browser_pk") != browser["pk"] or browser.get("oauth_tx") != tx["pk"] or tx["status"] != "pending":
            raise AuthError(409, "oauth_transaction_invalid", "로그인을 다시 시작해 주세요.")
        claimed = next_row(tx, status="exchanging")
        self.store.commit([(claimed, tx["version"])], [(browser["pk"], browser["version"])])
        refresh = None
        committed = False
        try:
            result = self.provider.exchange(body["code"], tx["verifier"])
            refresh = result.get("refresh_token")
            tokens = provider_tokens(result, now)
            current = self.active_browser(browser, int(self.clock()))
            if current.get("oauth_tx") != tx["pk"]:
                raise Conflict()
            sid = self.random()
            session = {"pk": key("SESSION", sid), "version": 0, "status": "active", "browser_pk": current["pk"], "session_ref": self.random(),
                       "expires_at": now + 86340, "ttl": now + 90000,
                       "provider_kind": "oauth", "provider_client_id": CLIENT, **tokens}
            finished = {k: v for k, v in next_row(claimed, status="complete").items() if k != "verifier"}
            updated_browser = next_row(current, session_pk=session["pk"], expires_at=now + 86400, ttl=now + 90000)
            updated_browser.pop("oauth_tx", None)
            changes = [(finished, claimed["version"]), (session, None), (updated_browser, current["version"])]
            old = self.store.read(current["session_pk"]) if current.get("session_pk") else None
            if old and old.get("status") in {"active", "refreshing"}:
                changes.append((redact_session(old, "revoked"), old["version"]))
            self.store.commit(changes)
            committed = True
            if old:
                self.revoke_best_effort(old.get("refresh_token"), old)
            outgoing.append(cookie(SESSION_COOKIE, sid, session["expires_at"] - int(self.clock())))
            return self.session_result(session)
        except (Conflict, AuthError):
            raise AuthError(409, "oauth_transaction_invalid", "로그인을 다시 시작해 주세요.") from None
        except Exception:
            raise AuthError(503, "oauth_exchange_unknown", "로그인 결과를 확인하지 못했습니다. 다시 로그인해 주세요.") from None
        finally:
            if not committed:
                self.revoke_best_effort(refresh)
                try:
                    self.store.commit([({k: v for k, v in next_row(claimed, status="unknown").items() if k != "verifier"}, claimed["version"])])
                except Exception:
                    pass

    def signin(self, browser, email, password, source_ip, now, outgoing):
        from .auth_native import quotas
        claimed = next_row(browser, signin_nonce=self.random(), expires_at=now + 86400, ttl=now + 90000)
        # Supersede an unfinished OAuth attempt without adopting its credentials.
        claimed.pop("oauth_tx", None)
        self.store.commit([(claimed, browser["version"]), *quotas(self.store,
            [("ip:" + source_ip, 30), ("email-browser:" + email + ":" + browser["pk"], 5)], now)])
        provenance = {"provider_kind": "native", "provider_client_id": self.native.client_id}
        refresh, committed = None, False
        try:
            value = self.native.authenticate(email, password)
            refresh = value.get("refresh_token")
            tokens = self.native.validate(value, int(self.clock()), expected_email=email)
            current = self.active_browser(browser, int(self.clock()))
            if current["version"] != claimed["version"] or current.get("signin_nonce") != claimed["signin_nonce"]:
                raise Conflict()
            sid = self.random()
            session = {"pk": key("SESSION", sid), "version": 0, "status": "active", "browser_pk": current["pk"],
                       "session_ref": self.random(), "expires_at": now + 86340, "ttl": now + 90000,
                       **provenance, **tokens}
            updated = next_row(current, session_pk=session["pk"])
            updated.pop("signin_nonce", None)
            changes = [(session, None), (updated, current["version"])]
            old = self.store.read(current["session_pk"]) if current.get("session_pk") else None
            if old and old.get("status") in {"active", "refreshing"}:
                changes.append((redact_session(old, "revoked"), old["version"]))
            self.store.commit(changes)
            committed = True
            if old:
                self.revoke_best_effort(old.get("refresh_token"), old)
            outgoing.append(cookie(SESSION_COOKIE, sid, session["expires_at"] - int(self.clock())))
            return self.session_result(session)
        except (Conflict, AuthError):
            raise AuthError(409, "signin_cancelled", "로그인 요청 상태가 바뀌었습니다. 다시 로그인해 주세요.") from None
        except ProviderError as error:
            if error.definitive:
                raise AuthError(401, "invalid_credentials", "이메일 또는 비밀번호를 확인해 주세요.") from None
            raise AuthError(503, "signin_unavailable", "로그인 결과를 확인하지 못했습니다. 다시 시도해 주세요.") from None
        except Exception:
            raise AuthError(503, "signin_unavailable", "로그인 결과를 확인하지 못했습니다. 다시 시도해 주세요.") from None
        finally:
            if not committed:
                self.revoke_best_effort(refresh, provenance)
                cleaned = next_row(claimed)
                cleaned.pop("signin_nonce", None)
                try:
                    self.store.commit([(cleaned, claimed["version"])])
                except Exception:
                    pass

    @staticmethod
    def session_result(row):
        return {"authenticated": True, "access_token": row["access_token"], "expires_at": row["access_expires_at"] * 1000,
                "session_ref": row["session_ref"]}

    def session(self, browser, cookies, now, outgoing):
        sid = cookies.get(SESSION_COOKIE)
        row = self.store.read(key("SESSION", sid)) if sid else None
        if expired(row, now) or row.get("browser_pk") != browser["pk"] or browser.get("session_pk") != row["pk"] or row["status"] not in {"active", "refreshing"}:
            return {"authenticated": False}
        provider = self.session_provider(row)
        if row["status"] == "refreshing":
            if row.get("refresh_deadline", 0) > now:
                raise AuthError(409, "session_refreshing", "로그인 정보를 갱신하고 있습니다.", 1)
            try:
                self.store.commit([(redact_session(row, "expired"), row["version"])])
            except Conflict:
                pass
            return {"authenticated": False}
        if row["access_expires_at"] > now + 60:
            return self.session_result(row)
        claimed = next_row(row, status="refreshing", refresh_deadline=now + 30)
        try:
            self.store.commit([(claimed, row["version"])], [(browser["pk"], browser["version"])])
        except Conflict:
            raise AuthError(409, "session_refreshing", "로그인 정보를 갱신하고 있습니다.", 1) from None
        refreshed = None
        committed = False
        try:
            raw = (provider.refresh(row["refresh_token"], row["sub"]) if row.get("provider_kind") == "native"
                   else provider.refresh(row["refresh_token"]))
            refreshed = raw.get("refresh_token")
            tokens = (provider.validate(raw, int(self.clock()), fallback_refresh=row["refresh_token"],
                                        expected_sub=row["sub"], expected_email=row["native_email"])
                      if row.get("provider_kind") == "native"
                      else provider_tokens(raw, now, row["refresh_token"], row["sub"]))
            current_browser = self.active_browser(browser, int(self.clock()))
            if current_browser.get("session_pk") != row["pk"]:
                raise Conflict()
            updated = next_row(claimed, status="active", **tokens)
            updated.pop("refresh_deadline", None)
            self.store.commit([(updated, claimed["version"])], [(current_browser["pk"], current_browser["version"])])
            committed = True
            return self.session_result(updated)
        except Exception:
            try:
                self.store.commit([(redact_session(claimed, "expired"), claimed["version"])])
            except Exception:
                pass
            raise AuthError(401, "authentication_required", "로그인이 만료됐습니다. 다시 로그인해 주세요.") from None
        finally:
            if not committed:
                self.revoke_best_effort(refreshed or row.get("refresh_token"), row)

    def logout(self, browser, outgoing):
        token, session = None, None
        # A callback/refresh may have committed just before logout. Re-read the
        # browser's current session and atomically revoke both rows. Pending
        # callbacks must also check this browser row before creating a session.
        for _ in range(4):
            current = self.store.read(browser["pk"])
            if not current or current["status"] != "active":
                break
            changes = [(next_row(current, status="revoked"), current["version"])]
            session = self.store.read(current["session_pk"]) if current.get("session_pk") else None
            if session and session["status"] in {"active", "refreshing"}:
                changes.append((redact_session(session, "revoked"), session["version"]))
            transaction = self.store.read(current["oauth_tx"]) if current.get("oauth_tx") else None
            if transaction and transaction["status"] in {"pending", "exchanging"}:
                changes.append((redact_session(transaction, "revoked"), transaction["version"]))
            try:
                self.store.commit(changes)
                token = session.get("refresh_token") if session else None
                break
            except Conflict:
                continue
        else:
            raise AuthError(409, "logout_conflict", "로그아웃을 다시 요청해 주세요.")
        self.revoke_best_effort(token, session)
        # Revocation is authoritative. A delayed cookie deletion could erase a
        # newer login established by another tab after this transaction.
        return {"logged_out": True, "logout_url": DOMAIN + "/logout?" + urlencode({"client_id": CLIENT, "logout_uri": ORIGIN + "/"})}

    def handle(self, event):
        outgoing = []
        try:
            method = event.get("httpMethod", "GET").upper()
            path = event.get("path", "")
            body = post_body(event) if method == "POST" else None
            cookies = parse_cookies(event)
            now = int(self.clock())
            if method == "GET" and path == "/api/auth/session":
                try:
                    browser = self.browser(cookies, now, outgoing)
                except AuthError:
                    # A read must never replace a binding established by a
                    # later explicit login/signup while this response travels.
                    return response(200, {"authenticated": False})
                return response(200, self.session(browser, cookies, now, outgoing), outgoing)
            if method == "GET" and path == "/api/auth/login":
                browser = self.browser(cookies, now, outgoing, create=True)
                if cookies.get(BROWSER_COOKIE) and key("BROWSER", cookies[BROWSER_COOKIE]) == browser["pk"]:
                    outgoing.append(cookie(BROWSER_COOKIE, cookies[BROWSER_COOKIE], 86400))
                return response(302, {}, outgoing, self.login(browser, event.get("queryStringParameters") or {}, now))
            if method != "POST":
                raise AuthError(404, "not_found", "요청한 경로를 찾지 못했습니다.")
            if path == "/api/auth/logout" and set(body) == set():
                try:
                    browser = self.browser(cookies, now, outgoing)
                except AuthError:
                    return response(200, {"logged_out": True, "logout_url": DOMAIN + "/logout?" + urlencode({"client_id": CLIENT, "logout_uri": ORIGIN + "/"})}, outgoing)
                return response(200, self.logout(browser, outgoing), outgoing)
            if path == "/api/auth/signin":
                if self.native is None:
                    raise AuthError(503, "signin_unavailable", "로그인 서비스에 연결하지 못했습니다.")
                from .auth_native import credentials, quotas, source_address
                email, password = credentials(body)
                source_ip = source_address(((event.get("requestContext") or {}).get("identity") or {}).get("sourceIp"))
                try:
                    browser = self.browser(cookies, now, outgoing)
                except AuthError:
                    # Establish the stable browser before any password attempt.
                    # A cookie-less concurrent logout cannot identify this row.
                    self.store.commit(quotas(self.store, [("binding-ip:" + source_ip, 30)], now))
                    self.browser(cookies, now, outgoing, create=True)
                    return response(409, {"code": "signin_binding_required", "message": "로그인 연결을 준비했습니다."}, outgoing)
                value = self.signin(browser, email, password, source_ip, now, outgoing)
                outgoing.append(cookie(BROWSER_COOKIE, cookies[BROWSER_COOKIE], 86400))
                return response(200, value, outgoing)
            browser = self.browser(cookies, now, outgoing, create=path == "/api/auth/signup/start" and self.signup is not None)
            if path == "/api/auth/callback":
                value = self.callback(browser, body, now, outgoing)
                outgoing.append(cookie(BROWSER_COOKIE, cookies[BROWSER_COOKIE], 86400))
                return response(200, value, outgoing)
            if path.startswith("/api/auth/signup/") and self.signup:
                source_ip = ((event.get("requestContext") or {}).get("identity") or {}).get("sourceIp")
                result = self.signup.handle(path.rsplit("/", 1)[-1], browser, body, now, source_ip)
                return response(200, result, outgoing)
            raise AuthError(404, "not_found", "요청한 경로를 찾지 못했습니다.")
        except AuthError as error:
            return response(error.status, public_error(error), outgoing)
        except Conflict:
            return response(409, {"code": "state_conflict", "message": "요청 상태가 바뀌었습니다. 다시 확인해 주세요."}, outgoing)
        except Exception:
            # Intentionally no request/body/SDK exception logging.
            return response(503, {"code": "auth_service_unavailable", "message": "인증 서비스에 연결하지 못했습니다. 잠시 후 다시 시도해 주세요."}, outgoing)


_APP = None


def aws_app():
    import boto3
    from botocore.config import Config
    sdk = boto3.Session(region_name="ap-northeast-2")
    config = Config(retries={"total_max_attempts": 1}, connect_timeout=5, read_timeout=10)
    store = DynamoAuthStore(sdk.client("dynamodb", config=config), os.environ["WEB_AUTH_TABLE"])
    signup, signup_client_id = None, None
    if os.environ.get("WEB_SIGNUP_SECRET_ARN"):
        from .auth_signup import CognitoSignup, SignupService
        secret = json.loads(sdk.client("secretsmanager", config=config).get_secret_value(
            SecretId=os.environ["WEB_SIGNUP_SECRET_ARN"])["SecretString"])
        signup_client_id = secret["client_id"]
        signup = SignupService(store, CognitoSignup(sdk.client("cognito-idp", config=config), secret["client_id"], secret["client_secret"]))
    native = None
    if os.environ.get("WEB_LOGIN_SECRET_ARN"):
        from .auth_native import CognitoNative
        secret = json.loads(sdk.client("secretsmanager", config=config).get_secret_value(
            SecretId=os.environ["WEB_LOGIN_SECRET_ARN"])["SecretString"])
        native = CognitoNative(sdk.client("cognito-idp", config=config), secret["client_id"], secret["client_secret"],
                               signup_client_id=signup_client_id)
    return AuthService(store, CognitoOAuth(), signup=signup, native=native)


def handler(event, context):
    global _APP
    if _APP is None:
        _APP = aws_app()
    return _APP.handle(event)
