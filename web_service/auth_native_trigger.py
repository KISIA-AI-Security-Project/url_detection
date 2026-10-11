"""V2 access scope customization for one dedicated private login client only."""
from copy import deepcopy
import os
import re

from .auth_sessions import email_address

POOL = "ap-northeast-2_dlm4zCq7C"
REGION = "ap-northeast-2"
PUBLIC_CLIENT = "11v9bek84i6fakpvhtk5nk4sth"


def customize(event, *, login_client_id, signup_client_id):
    if (not isinstance(login_client_id, str) or not re.fullmatch(r"[A-Za-z0-9_+]{1,128}", login_client_id)
            or not isinstance(signup_client_id, str) or not signup_client_id
            or login_client_id in {PUBLIC_CLIENT, signup_client_id}):
        raise ValueError("dedicated_login_client_required")
    if (event.get("callerContext") or {}).get("clientId") != login_client_id:
        # Existing OAuth and signup tokens keep exactly their existing behavior.
        return event
    try:
        if (event.get("version") != "2" or event.get("userPoolId") != POOL or event.get("region") != REGION
                or event.get("triggerSource") not in {"TokenGeneration_Authentication", "TokenGeneration_RefreshTokens"}):
            raise ValueError()
        attributes = event["request"]["userAttributes"]
        sub = attributes["sub"]
        if (not isinstance(sub, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", sub)
                or attributes.get("email_verified") != "true"):
            raise ValueError()
        email_address(attributes.get("email"))
        result = deepcopy(event)
        # This exact client has no OAuth grants; its only public access scope is
        # the existing analysis scope. Never expose Cognito self-service powers.
        result["response"] = {"claimsAndScopeOverrideDetails": {"accessTokenGeneration": {
            "scopesToAdd": ["team5-web/analysis"],
            "scopesToSuppress": ["aws.cognito.signin.user.admin"],
        }}}
        return result
    except Exception:
        # Do not log the event or echo attributes/credentials in trigger errors.
        raise ValueError("login_token_request_rejected") from None


def handler(event, context):
    return customize(event, login_client_id=os.environ.get("WEB_LOGIN_CLIENT_ID"),
                     signup_client_id=os.environ.get("WEB_SIGNUP_CLIENT_ID"))
