"""Email-first signup using Cognito-owned codes and a server-only client.

Only a successful new SignUp UserSub plus authentication with this flow's random
password can authorize ChangePassword. No administrative password/reset API is
used. Existing accounts and ambiguous SignUp outcomes are never adopted.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
import re
import secrets
from .auth_sessions import AuthError, Conflict, digest, email_address, expired, key, next_row, password


def error_code(error):
    return getattr(error, "response", {}).get("Error", {}).get("Code", "unknown")


class CognitoSignup:
    def __init__(self, client, client_id, client_secret):
        if not isinstance(client_id, str) or not client_id or client_id == "11v9bek84i6fakpvhtk5nk4sth" or not isinstance(client_secret, str) or not 24 <= len(client_secret) <= 64:
            raise ValueError("private_signup_client_required")
        self.client, self.client_id, self.secret = client, client_id, client_secret

    def secret_hash(self, email):
        return base64.b64encode(hmac.new(self.secret.encode(), (email + self.client_id).encode(), hashlib.sha256).digest()).decode()

    def start(self, email, placeholder):
        return self.client.sign_up(ClientId=self.client_id, SecretHash=self.secret_hash(email),
            Username=email, Password=placeholder, UserAttributes=[{"Name": "email", "Value": email}])

    def confirm(self, email, code):
        return self.client.confirm_sign_up(ClientId=self.client_id, SecretHash=self.secret_hash(email),
            Username=email, ConfirmationCode=code, ForceAliasCreation=False)

    def resend(self, email):
        return self.client.resend_confirmation_code(ClientId=self.client_id, SecretHash=self.secret_hash(email), Username=email)

    def authenticate(self, email, placeholder):
        return self.client.initiate_auth(ClientId=self.client_id, AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": email, "PASSWORD": placeholder, "SECRET_HASH": self.secret_hash(email)})

    def user(self, access_token):
        return self.client.get_user(AccessToken=access_token)

    def change(self, access_token, old, new):
        return self.client.change_password(AccessToken=access_token, PreviousPassword=old, ProposedPassword=new)

    def revoke(self, refresh_token):
        return self.client.revoke_token(ClientId=self.client_id, ClientSecret=self.secret, Token=refresh_token)


RECOVERY = "가입이 이미 시작됐을 수 있습니다. 로그인 화면에서 기존 이메일 인증을 완료한 뒤 비밀번호 찾기를 이용해 주세요."


class SignupService:
    def __init__(self, store, provider, *, random_password=lambda: secrets.token_urlsafe(32) + "Aa1!"):
        self.store, self.provider, self.random_password = store, provider, random_password

    def public(self, row, now):
        if row["status"] == "complete":
            return {"intent_id": row["intent_id"], "status": "complete", "login_required": True}
        if row["status"] not in {"code_sent", "verified"}:
            code = "completion_unknown" if row["status"] in {"committing", "completion_unknown"} else "verification_unknown"
            raise AuthError(409, code, RECOVERY)
        value = {"intent_id": row["intent_id"], "status": row["status"], "email": row["email"],
                 "expires_at": row["expires_at"] * 1000,
                 "retry_after_seconds": max(0, row.get("resend_at", 0) - now) if row["status"] == "code_sent" else 0}
        if row.get("masked_destination"):
            value["masked_destination"] = row["masked_destination"]
        return value

    def quotas(self, email, browser, now, source_ip):
        changes = []
        day = now // 86400
        for identity, limit, spacing in (("email:" + email, 5, 60), ("browser:" + browser["pk"], 15, 5), ("ip:" + source_ip, 20, 1), ("global", 45, 0)):
            pk = key("SIGNUP_QUOTA", str(day) + ":" + identity)
            old = self.store.read(pk)
            if old and (old["count"] >= limit or old.get("next_at", 0) > now):
                retry = max(1, old.get("next_at", 0) - now) if old["count"] < limit else 86400 - now % 86400
                raise AuthError(429, "rate_limited", "인증 메일 요청이 많습니다. 잠시 후 다시 시도해 주세요.", retry)
            row = {"pk": pk, "version": old["version"] + 1 if old else 0,
                   "count": old["count"] + 1 if old else 1, "next_at": now + spacing,
                   "expires_at": (day + 1) * 86400, "ttl": (day + 2) * 86400}
            changes.append((row, old["version"] if old else None))
        return changes

    @staticmethod
    def delivery(result):
        value = result.get("CodeDeliveryDetails") or {}
        destination = value.get("Destination")
        if value.get("DeliveryMedium") != "EMAIL" or not isinstance(destination, str) or not 1 <= len(destination) <= 254:
            raise ValueError("email_delivery_response_required")
        return destination

    def changed(self, row, browser, **values):
        updated = next_row(row, **values)
        self.store.commit([(updated, row["version"])], [(browser["pk"], browser["version"])])
        return updated

    def terminal(self, row, status):
        updated = next_row(row, status=status)
        updated.pop("placeholder", None)
        try:
            self.store.commit([(updated, row["version"])])
        except Exception:
            pass

    def start(self, browser, body, now, pk, source_ip):
        email = email_address(body["email"])
        old = self.store.read(pk)
        if old:
            if expired(old, now):
                raise AuthError(410, "flow_expired", RECOVERY)
            if old["email"] != email:
                raise AuthError(409, "flow_conflict", "이메일이 바뀌었습니다. 새 인증 요청을 시작해 주세요.")
            return self.public(old, now)
        row = {"pk": pk, "version": 0, "status": "starting", "browser_pk": browser["pk"],
               "intent_id": body["intent_id"], "email": email, "placeholder": self.random_password(),
               "expires_at": now + 600, "hard_expires_at": now + 1800, "ttl": now + 3600,
               "resend_at": now + 60, "resends": 0, "attempts": 0}
        self.store.commit([(row, None), *self.quotas(email, browser, now, source_ip)], [(browser["pk"], browser["version"])])
        try:
            result = self.provider.start(email, row["placeholder"])
            sub = result.get("UserSub")
            if not isinstance(sub, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", sub) or result.get("UserConfirmed") is not False:
                raise ValueError("new_unconfirmed_user_sub_required")
            updated = self.changed(row, browser, status="code_sent", sub=sub, masked_destination=self.delivery(result))
            return self.public(updated, now)
        except Exception as error:
            self.terminal(row, "signup_unknown")
            if error_code(error) == "UsernameExistsException":
                raise AuthError(409, "account_exists", RECOVERY) from None
            raise AuthError(409, "verification_unknown", "메일 발송 또는 가입 접수 결과를 확인하지 못했습니다. " + RECOVERY) from None

    def resend(self, browser, row, now, source_ip):
        if row["status"] != "code_sent":
            return self.public(row, now)
        if row["resends"] >= 3:
            raise AuthError(429, "rate_limited", "인증 메일 재전송 횟수를 초과했습니다.", max(1, row["expires_at"] - now))
        if row["resend_at"] > now:
            raise AuthError(429, "rate_limited", "잠시 후 인증 메일을 다시 요청해 주세요.", row["resend_at"] - now)
        claimed = next_row(row, status="resending", resends=row["resends"] + 1, resend_at=now + 60)
        self.store.commit([(claimed, row["version"]), *self.quotas(row["email"], browser, now, source_ip)], [(browser["pk"], browser["version"])])
        try:
            result = self.provider.resend(row["email"])
            updated = self.changed(claimed, browser, status="code_sent", masked_destination=self.delivery(result),
                                   expires_at=min(now + 600, row["hard_expires_at"]))
            return self.public(updated, now)
        except Exception:
            # The original UserSub ownership remains proven. The user may try a
            # received code; neither old nor new code is accepted without Cognito.
            try:
                self.changed(claimed, browser, status="code_sent")
            except Exception:
                pass
            raise AuthError(503, "auth_provider_unavailable", "메일 재전송 결과를 확인하지 못했습니다. 받은 코드가 있다면 확인해 주세요.", 60) from None

    def confirm(self, browser, row, body, now):
        if row["status"] == "verified":
            return self.public(row, now)
        if row["status"] != "code_sent":
            return self.public(row, now)
        code = body["code"]
        if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
            raise AuthError(400, "code_mismatch", "메일로 받은 6자리 인증 코드를 입력해 주세요.")
        if row["attempts"] >= 5:
            raise AuthError(429, "rate_limited", "인증 시도 횟수를 초과했습니다.", max(1, row["expires_at"] - now))
        claimed = self.changed(row, browser, status="confirming", attempts=row["attempts"] + 1)
        try:
            self.provider.confirm(row["email"], code)
            updated = self.changed(claimed, browser, status="verified", expires_at=min(now + 300, row["hard_expires_at"]))
            return self.public(updated, now)
        except Exception as error:
            code = error_code(error)
            if code in {"CodeMismatchException", "ExpiredCodeException", "TooManyRequestsException", "TooManyFailedAttemptsException"}:
                self.changed(claimed, browser, status="code_sent")
                if code == "CodeMismatchException":
                    raise AuthError(400, "code_mismatch", "인증 코드가 일치하지 않습니다.") from None
                if code == "ExpiredCodeException":
                    raise AuthError(410, "code_expired", "인증 코드가 만료됐습니다. 새 코드를 받아 주세요.") from None
                raise AuthError(429, "rate_limited", "인증 시도가 많습니다. 잠시 후 다시 시도해 주세요.", 60) from None
            self.terminal(claimed, "verification_unknown")
            raise AuthError(409, "verification_unknown", "인증 결과를 확인하지 못했습니다. " + RECOVERY) from None

    def complete(self, browser, row, body, now):
        new_password = password(body["password"])
        if row["status"] == "complete":
            return self.public(row, now)
        if row["status"] != "verified":
            if row["status"] == "code_sent":
                raise AuthError(409, "flow_conflict", "이메일 인증을 먼저 완료해 주세요.")
            return self.public(row, now)
        claimed = self.changed(row, browser, status="completing")
        refresh = None
        changing = False
        try:
            result = self.provider.authenticate(row["email"], row["placeholder"])
            tokens = result.get("AuthenticationResult")
            if result.get("ChallengeName") or not isinstance(tokens, dict) or not all(isinstance(tokens.get(k), str) and tokens[k] for k in ("AccessToken", "RefreshToken")):
                raise ValueError("private_authentication_result_required")
            refresh = tokens["RefreshToken"]
            user = self.provider.user(tokens["AccessToken"])
            attributes = {x["Name"]: x["Value"] for x in user.get("UserAttributes", [])}
            if attributes.get("sub") != row["sub"] or email_address(attributes.get("email")) != row["email"] or attributes.get("email_verified") != "true":
                raise ValueError("new_account_provider_identity_mismatch")
            # Atomic fence before the only password mutation. Never reclaim this
            # state after a timeout or crashed worker: its outcome is ambiguous.
            claimed = self.changed(claimed, browser, status="committing")
            changing = True
            self.provider.change(tokens["AccessToken"], row["placeholder"], new_password)
            finished = next_row(claimed, status="complete", expires_at=row["hard_expires_at"], revoke_status="pending")
            finished.pop("placeholder", None)
            self.store.commit([(finished, claimed["version"])])
            return self.public(finished, now)
        except Exception:
            self.terminal(claimed, "completion_unknown" if changing else "verification_unknown")
            code = "completion_unknown" if changing else "verification_unknown"
            raise AuthError(409, code, "가입 완료 결과를 확인하지 못했습니다. 로그인하거나 비밀번호 찾기를 이용해 주세요.") from None
        finally:
            if refresh:
                revoked = False
                try:
                    self.provider.revoke(refresh)
                    revoked = True
                except Exception:
                    # Never re-run ChangePassword because token cleanup failed.
                    pass
                try:
                    current = self.store.read(row["pk"])
                    if current and current["status"] in {"complete", "completion_unknown", "verification_unknown"}:
                        self.store.commit([(next_row(current, revoke_status="confirmed" if revoked else "unknown"), current["version"])])
                except Exception:
                    pass

    def handle(self, action, browser, body, now, source_ip=None):
        fields = {"start": {"email", "intent_id"}, "confirm": {"intent_id", "code"},
                  "resend": {"intent_id"}, "complete": {"intent_id", "password"}}
        if action not in fields or set(body) != fields[action] or not isinstance(body.get("intent_id"), str) or not re.fullmatch(r"[A-Za-z0-9_-]{20,128}", body["intent_id"]):
            raise AuthError(400, "bad_request", "가입 요청 형식을 확인해 주세요.")
        try:
            source_ip = str(ipaddress.ip_address(source_ip))
        except ValueError:
            raise AuthError(503, "auth_provider_unavailable", "요청 연결 정보를 확인하지 못했습니다.") from None
        pk = key("SIGNUP", browser["pk"] + ":" + body["intent_id"])
        try:
            if action == "start":
                return self.start(browser, body, now, pk, source_ip)
            row = self.store.read(pk)
            if expired(row, now):
                raise AuthError(410, "flow_expired", RECOVERY)
            if row.get("browser_pk") != browser["pk"] or not row.get("sub"):
                raise AuthError(409, "verification_unknown", RECOVERY)
            if action == "resend":
                return self.resend(browser, row, now, source_ip)
            if action == "confirm":
                return self.confirm(browser, row, body, now)
            return self.complete(browser, row, body, now)
        except Conflict:
            raise AuthError(409, "flow_conflict", "다른 인증 요청을 처리하고 있습니다. 잠시 후 상태를 확인해 주세요.") from None
