"""Server-only Cognito password login. Never accepts browser-supplied tokens."""
from __future__ import annotations
import base64
import hashlib
import hmac
import ipaddress
import json
import re

from .auth_sessions import AuthError, email_address, key
from .auth_service import CLIENT, ISSUER, ProviderError, provider_tokens

ANALYSIS_SCOPE = "team5-web/analysis"


def source_address(value):
    try:
        return str(ipaddress.ip_address(value))
    except (ValueError, TypeError):
        raise AuthError(503, "signin_unavailable", "요청 연결 정보를 확인하지 못했습니다.") from None


def credentials(body):
    if set(body) != {"email", "password"}:
        raise AuthError(400, "bad_request", "이메일과 비밀번호를 입력해 주세요.")
    email = email_address(body["email"])
    # Login must not reapply the new-signup password policy to existing users.
    value = body["password"]
    if not isinstance(value, str) or not 1 <= len(value) <= 256:
        raise AuthError(400, "bad_request", "이메일과 비밀번호를 입력해 주세요.")
    return email, value


def quotas(store, identities, now, *, period=900):
    """Hashed identities only; callers atomically commit these before the SDK call."""
    changes = []
    bucket = now // period
    for identity, limit in identities:
        pk = key("SIGNIN_QUOTA", str(period) + ":" + str(bucket) + ":" + identity)
        old = store.read(pk)
        if old and old["count"] >= limit:
            raise AuthError(429, "rate_limited", "로그인 요청이 많습니다. 잠시 후 다시 시도해 주세요.",
                            (bucket + 1) * period - now)
        changes.append(({"pk": pk, "version": old["version"] + 1 if old else 0,
                         "count": old["count"] + 1 if old else 1,
                         "expires_at": (bucket + 1) * period, "ttl": (bucket + 2) * period},
                        old["version"] if old else None))
    return changes


class CognitoNative:
    def __init__(self, client, client_id, client_secret, *, signup_client_id):
        if (not isinstance(client_id, str) or not re.fullmatch(r"[A-Za-z0-9_+]{1,128}", client_id)
                or client_id in {CLIENT, signup_client_id}
                or not isinstance(signup_client_id, str) or not signup_client_id
                or not isinstance(client_secret, str) or not 24 <= len(client_secret) <= 64):
            raise ValueError("dedicated_private_login_client_required")
        self.client, self.client_id, self.secret = client, client_id, client_secret

    def secret_hash(self, username):
        return base64.b64encode(hmac.new(self.secret.encode(), (username + self.client_id).encode(),
                                         hashlib.sha256).digest()).decode()

    def request(self, flow, parameters):
        try:
            value = self.client.initiate_auth(ClientId=self.client_id, AuthFlow=flow, AuthParameters=parameters)
        except Exception as error:
            code = getattr(error, "response", {}).get("Error", {}).get("Code")
            # No account existence/status distinctions or provider error strings.
            definitive = code in {"NotAuthorizedException", "UserNotFoundException",
                                  "UserNotConfirmedException", "PasswordResetRequiredException"}
            raise ProviderError(definitive) from None
        result = value.get("AuthenticationResult")
        if value.get("ChallengeName") or not isinstance(result, dict):
            raise ProviderError(True)
        return {"access_token": result.get("AccessToken"), "id_token": result.get("IdToken"),
                "refresh_token": result.get("RefreshToken"), "expires_in": result.get("ExpiresIn")}

    def authenticate(self, email, password):
        return self.request("USER_PASSWORD_AUTH", {"USERNAME": email, "PASSWORD": password,
                            "SECRET_HASH": self.secret_hash(email)})

    def refresh(self, refresh_token, sub):
        # This pool uses email as UsernameAttributes: refresh HMAC uses sub,
        # not the entered email or the mutable email attribute.
        return self.request("REFRESH_TOKEN_AUTH", {"REFRESH_TOKEN": refresh_token,
                            "SECRET_HASH": self.secret_hash(sub)})

    def revoke(self, refresh_token):
        return self.client.revoke_token(ClientId=self.client_id, ClientSecret=self.secret, Token=refresh_token)

    def validate(self, value, now, *, fallback_refresh=None, expected_sub=None, expected_email=None):
        try:
            tokens = provider_tokens(value, now, fallback_refresh, expected_sub, expected_client=self.client_id)
            token = value["id_token"]
            if not isinstance(token, str) or len(token) > 16384:
                raise ValueError()
            parts = token.split(".")
            if len(parts) != 3:
                raise ValueError()
            def decode(part):
                return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
            header, claims = decode(parts[0]), decode(parts[1])
            if (header.get("alg") != "RS256" or not header.get("kid") or claims.get("iss") != ISSUER
                    or claims.get("aud") != self.client_id or claims.get("token_use") != "id"
                    or claims.get("sub") != tokens["sub"] or claims.get("email_verified") is not True
                    or type(claims.get("exp")) is not int or claims["exp"] <= now + 5):
                raise ValueError()
            email = email_address(claims.get("email"))
            if expected_email is not None and email != expected_email:
                raise ValueError()
            access = decode(tokens["access_token"].split(".")[1])
            if set(access["scope"].split()) != {ANALYSIS_SCOPE}:
                raise ValueError()
            return {**tokens, "native_email": email}
        except Exception:
            raise ProviderError() from None
