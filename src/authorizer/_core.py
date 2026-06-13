"""I/O-free request building and response parsing shared by both clients."""

from __future__ import annotations

import json as _json
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

from .exceptions import AuthorizerError


@dataclass
class ClientConfig:
    client_id: str
    authorizer_url: str
    redirect_url: str
    extra_headers: dict[str, str]


@dataclass
class RequestSpec:
    method: str
    url: str
    headers: dict[str, str]
    json: dict[str, Any] = field(default_factory=dict)


def _origin_from_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return None


def build_headers(config: ClientConfig, per_call: dict[str, str] | None) -> dict[str, str]:
    """Assemble headers: identity headers, extra headers, per-call overrides, default Origin."""
    headers: dict[str, str] = {
        "Content-Type": "application/json",
        "x-authorizer-url": config.authorizer_url,
        "x-authorizer-client-id": config.client_id,
    }
    headers.update(config.extra_headers)
    if per_call:
        headers.update(per_call)
    # CSRF guard (Authorizer >= v2.3.0) needs an Origin on state-changing requests.
    # The server's own origin always passes the same-origin rule under wildcard
    # ALLOWED_ORIGINS. Callers may override via extra/per-call headers.
    if "Origin" not in headers:
        origin = _origin_from_url(config.authorizer_url)
        if origin:
            headers["Origin"] = origin
    return headers


def build_graphql_request(
    authorizer_url: str,
    query: str,
    variables: dict[str, Any] | None,
    headers: dict[str, str],
) -> RequestSpec:
    body: dict[str, Any] = {"query": query}
    if variables:
        body["variables"] = variables
    return RequestSpec("POST", f"{authorizer_url}/graphql", headers, body)


def build_oauth_request(
    authorizer_url: str,
    path: str,
    body: dict[str, Any],
    headers: dict[str, str],
) -> RequestSpec:
    return RequestSpec("POST", f"{authorizer_url}{path}", headers, body)


def _decode(body: bytes) -> Any:
    if not body:
        return None
    try:
        return _json.loads(body)
    except ValueError:
        return None


def parse_graphql_response(status: int, body: bytes, field_name: str) -> dict[str, Any] | None:
    """Return ``data[field_name]`` or raise AuthorizerError.

    Mirrors authorizer-go: a non-empty ``errors`` array is an API error; a
    >=400 status with no ``errors`` array (CSRF 403, proxy page) is also an error.
    """
    decoded = _decode(body)
    if isinstance(decoded, dict):
        errors = decoded.get("errors")
        if errors:
            message = "request failed"
            if isinstance(errors, list) and errors:
                first = errors[0]
                if isinstance(first, dict) and first.get("message"):
                    message = str(first["message"])
            raise AuthorizerError(
                message,
                errors=errors if isinstance(errors, list) else [errors],
                status=status,
            )
    if status >= 400:
        text = body.decode("utf-8", "replace") if body else ""
        raise AuthorizerError(f"HTTP {status}: {text}".strip(), status=status)
    if isinstance(decoded, dict):
        data = decoded.get("data")
        if isinstance(data, dict):
            return data.get(field_name)
    return None


def parse_oauth_response(status: int, body: bytes) -> dict[str, Any]:
    """Return parsed OAuth JSON or raise AuthorizerError using error fields."""
    decoded = _decode(body)
    payload: dict[str, Any] = decoded if isinstance(decoded, dict) else {}
    if status >= 400:
        message = str(
            payload.get("error_description") or payload.get("error") or f"HTTP {status}"
        )
        raise AuthorizerError(message, status=status)
    return payload
