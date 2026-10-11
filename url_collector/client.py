"""리다이렉트와 본문 크기가 제한된 공통 HTTP(S) 수집기."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import urljoin
from uuid import uuid4

import httpx

from .errors import CollectionError
from .models import PageSnapshot, RedirectHop
from .policy import CollectionPolicy
from .ssrf import (
    PinnedHTTPTransport,
    Resolver,
    ResolvedTarget,
    resolve_public_http_url,
    system_resolver,
)

_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


@dataclass(frozen=True, slots=True)
class _FinalResponse:
    url: str
    status_code: int
    headers: tuple[tuple[str, str], ...]
    body: bytes
    encoding: str | None
    truncated: bool
    errors: tuple[CollectionError, ...]


@dataclass(frozen=True, slots=True)
class _RedirectResponse:
    destination_url: str
    status_code: int
    location: str


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


class PartialReadError(Exception):
    def __init__(self, body, error):
        self.body, self.error = body, error

def _read_bounded_body(response, max_bytes):
    chunks = []
    size = 0
    try:
        for chunk in response.iter_bytes():
            remaining = max_bytes - size
            chunks.append(chunk[:max(remaining, 0)])
            size += min(len(chunk), max(remaining, 0))
            if len(chunk) > remaining:
                return b"".join(chunks), True
    except httpx.HTTPError as exc:
        raise PartialReadError(b"".join(chunks), exc) from exc
    return b"".join(chunks), False



def _request_once(
    url: str,
    *,
    target: ResolvedTarget,
    policy: CollectionPolicy,
    transport: httpx.BaseTransport | None,
    cookies: httpx.Cookies,
) -> _FinalResponse | _RedirectResponse:
    active_transport = (
        transport if transport is not None else PinnedHTTPTransport(target)
    )
    with httpx.Client(
        follow_redirects=False,
        timeout=policy.request_timeout_seconds,
        transport=active_transport,
        trust_env=False,
        headers={"User-Agent": policy.user_agent},
        cookies=cookies,
    ) as client:
        with client.stream("GET", url) as response:
            cookies.extract_cookies(response)
            headers = tuple(response.headers.multi_items())
            errors: list[CollectionError] = []
            if response.status_code in _REDIRECT_STATUSES:
                location = response.headers.get("location")
                if location is None:
                    errors.append(CollectionError.create('collection', 'redirect_without_location',
                        'redirect response has no Location header', url=url, status_code=response.status_code))
                else:
                    return _RedirectResponse(urljoin(url, location), response.status_code, location)
            try:
                body, truncated = _read_bounded_body(response, policy.max_body_bytes)
            except PartialReadError as exc:
                body, truncated = exc.body, True
                errors.append(CollectionError.create("http_body", "response_body_interrupted", str(exc.error),
                                                      received_bytes=len(body), error_type=type(exc.error).__name__, url=url))
            if response.status_code >= 400:
                errors.append(
                    CollectionError.create(
                        "collection",
                        "http_error_status",
                        "server returned an HTTP error status",
                        status_code=response.status_code,
                        url=str(response.url),
                    )
                )
            return _FinalResponse(
                str(response.url),
                response.status_code,
                headers,
                body,
                response.charset_encoding,
                truncated,
                tuple(errors),
            )


def _content_type(headers: tuple[tuple[str, str], ...]) -> str | None:
    for key, value in headers:
        if key.casefold() == "content-type":
            normalized = value.split(";", 1)[0].strip().lower()
            return normalized or None
    return None


def _snapshot(
    *,
    snapshot_id: str,
    collected_at: str,
    original_url: str,
    current_url: str,
    final_url: str | None,
    status_code: int | None,
    headers: tuple[tuple[str, str], ...],
    body: bytes,
    encoding: str | None,
    truncated: bool,
    redirect_chain: list[RedirectHop],
    errors: list[CollectionError],
    policy: CollectionPolicy,
) -> PageSnapshot:
    return PageSnapshot(
        snapshot_id=snapshot_id,
        collected_at=collected_at,
        original_url=original_url,
        current_url=current_url,
        final_url=final_url,
        status_code=status_code,
        response_headers=headers,
        body=body,
        captured_body_sha256=hashlib.sha256(body).hexdigest(),
        content_type=_content_type(headers),
        encoding=encoding,
        truncated=truncated,
        redirect_chain=tuple(redirect_chain),
        collection_errors=tuple(errors),
        request_profile=policy,
    )


def _failure_code(exc):
    if isinstance(exc, httpx.TimeoutException): return "request_timeout"
    if isinstance(exc, httpx.ConnectError): return "connection_failed"
    if isinstance(exc, ValueError):
        message = str(exc).lower()
        if "non-public" in message: return "target_policy_blocked"
        if "dns" in message: return "dns_resolution_failed"
        return "invalid_target"
    return "transport_error"


def collect_url(
    url: str,
    policy: CollectionPolicy,
    *,
    resolver: Resolver = system_resolver,
    transport: httpx.BaseTransport | None = None,
) -> PageSnapshot:
    """URL을 한 번의 논리적 여정으로 수집해 항상 ``PageSnapshot``을 반환한다."""
    snapshot_id = uuid4().hex
    collected_at = _now_iso()
    current_url = url
    cookies = httpx.Cookies()
    redirect_chain: list[RedirectHop] = []
    errors: list[CollectionError] = []

    for redirect_count in range(policy.max_redirects + 1):
        try:
            target = resolve_public_http_url(current_url, resolver)
            outcome = _request_once(
                current_url,
                target=target,
                cookies=cookies,
                policy=policy,
                transport=transport,
            )
        except (httpx.HTTPError, ValueError, OSError) as exc:
            errors.append(
                CollectionError.create(
                    "collection",
                    _failure_code(exc),
                    str(exc),
                    url=current_url,
                )
            )
            return _snapshot(
                snapshot_id=snapshot_id,
                collected_at=collected_at,
                original_url=url,
                current_url=current_url,
                final_url=None,
                status_code=None,
                headers=(),
                body=b"",
                encoding=None,
                truncated=False,
                redirect_chain=redirect_chain,
                errors=errors,
                policy=policy,
            )

        if isinstance(outcome, _FinalResponse):
            errors.extend(outcome.errors)
            return _snapshot(
                snapshot_id=snapshot_id,
                collected_at=collected_at,
                original_url=url,
                current_url=outcome.url,
                final_url=None if any(e.code=='redirect_without_location' for e in outcome.errors) else outcome.url,
                status_code=outcome.status_code,
                headers=outcome.headers,
                body=outcome.body,
                encoding=outcome.encoding,
                truncated=outcome.truncated,
                redirect_chain=redirect_chain,
                errors=errors,
                policy=policy,
            )

        redirect_chain.append(
            RedirectHop(
                source_url=current_url,
                destination_url=outcome.destination_url,
                status_code=outcome.status_code,
                location=outcome.location,
            )
        )
        if redirect_count >= policy.max_redirects:
            errors.append(
                CollectionError.create(
                    "collection",
                    "redirect_limit_exceeded",
                    "maximum redirect count exceeded",
                    url=outcome.destination_url,
                    limit=policy.max_redirects,
                )
            )
            return _snapshot(
                snapshot_id=snapshot_id,
                collected_at=collected_at,
                original_url=url,
                current_url=current_url,
                final_url=None,
                status_code=None,
                headers=(),
                body=b"",
                encoding=None,
                truncated=False,
                redirect_chain=redirect_chain,
                errors=errors,
                policy=policy,
            )
        current_url = outcome.destination_url

    raise RuntimeError("bounded request loop ended unexpectedly")


__all__ = ["Resolver", "collect_url", "system_resolver"]
