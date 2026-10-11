"""Transport the native Bash contract to the isolated investigation container."""
from urllib.parse import urlsplit

import httpx

from .tools.bash import BashInput, BashTool


class RemoteBash:
    def __init__(self, endpoint, *, max_timeout_ms, cleanup_timeout_ms):
        parsed = urlsplit(endpoint)
        if parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or parsed.username or parsed.password:
            raise ValueError("Bind Bash to the caller's loopback-only guest service")
        self.endpoint = endpoint.rstrip("/") + "/execute"
        self.timeout = (max_timeout_ms + cleanup_timeout_ms) / 1000 + 30

    async def execute(self, arguments):
        request = BashInput.model_validate(arguments).model_dump(mode="json")
        # Only the native command/timeout crosses this boundary. AWS and model
        # clients stay in the controller; the guest owns OS process cleanup.
        async with httpx.AsyncClient(trust_env=False, timeout=self.timeout) as client:
            response = await client.post(self.endpoint, json=request)
            response.raise_for_status()
            return response.json()

    def as_port(self):
        return BashTool.as_port(self)
