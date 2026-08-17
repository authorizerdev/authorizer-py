"""I/O-free request building and response parsing shared by both clients."""

from __future__ import annotations

import json as _json
from collections.abc import Iterable
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urlparse
from urllib.parse import urlsplit as _urlsplit

from .exceptions import AuthorizerError
from .types import GRANT_TYPE_TOKEN_EXCHANGE

# Supported transport protocols. ``graphql`` is the default (100% backward
# compatible). ``rest`` maps to the public/admin proto google.api.http paths;
# ``grpc`` calls the vendored stubs (requires the optional ``grpc`` extra).
PROTOCOLS = ("graphql", "rest", "grpc")


@dataclass
class ClientConfig:
    client_id: str
    authorizer_url: str
    redirect_url: str
    extra_headers: dict[str, str]
    protocol: str = "graphql"
    admin_secret: str = ""
    # Explicit gRPC endpoint (host:port). The server's gRPC listener runs on a
    # separate port (default 9091), not the HTTP URL's port. When unset, the
    # gRPC target is derived from ``authorizer_url``'s host with port 9091.
    grpc_endpoint: str = ""


# --------------------------------------------------------------------------- #
# Cookie carriage
#
# The server identifies an in-progress MFA session (and an admin_login session)
# ONLY by a cookie, so a client that drops cookies between calls can never
# redeem the withheld access token. gRPC already solved this with a plain
# name->value dict replayed as one `cookie` metadata entry; this is the same
# store for the HTTP transports, so both paths behave identically.
#
# It is deliberately NOT an http.cookiejar. A jar implements a user agent —
# domain matching, public-suffix rules, policy layering — and an SDK talks to
# exactly ONE origin, chosen by the caller at construction. Every one of those
# rules is either inapplicable or a source of the version-specific breakage the
# jar-based approach hit (`Secure` on http://localhost, dotless-domain matching,
# set_ok-vs-set_cookie layering). Origin scoping here is structural: the store is
# per-client and only ever replayed to that client's own base URL.
# --------------------------------------------------------------------------- #

CookieStore = dict[str, str]


def is_loopback_host(host: str) -> bool:
    """True for hosts a browser treats as a trustworthy origin over plain http."""
    host = (host or "").lstrip(".").lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


def absorb_set_cookie(
    values: Iterable[str], store: CookieStore, *, origin_is_secure: bool = True
) -> None:
    """Record `Set-Cookie` values into *store* (in place).

    ``origin_is_secure`` is https-or-loopback for the client's single origin. A
    ``Secure`` cookie is not recorded for an insecure origin, mirroring
    RFC 6265 §4.1.2.5 and what browsers, and Go's stdlib jar, do — loopback
    included, since the Secure Contexts spec makes it trustworthy.
    """
    for value in values:
        parsed: Any = SimpleCookie()
        parsed.load(value)
        for name, morsel in parsed.items():
            if morsel["secure"] and not origin_is_secure:
                continue
            try:
                # A zero/negative Max-Age is the server DELETING the cookie
                # (logout, DeleteMfaSession) — drop it rather than replay it.
                expired = int(morsel["max-age"]) <= 0
            except (TypeError, ValueError):
                expired = False
            if expired:
                store.pop(name, None)
            else:
                store[name] = morsel.value


def cookie_header(store: CookieStore) -> str | None:
    """The `Cookie` request header for *store*, or None when empty."""
    if not store:
        return None
    return "; ".join(f"{k}={v}" for k, v in store.items())


def origin_is_secure(url: str) -> bool:
    """Whether this client's single origin may carry a `Secure` cookie."""
    parts = _urlsplit(url)
    return parts.scheme == "https" or is_loopback_host(parts.hostname or "")


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
    if config.admin_secret:
        headers["x-authorizer-admin-secret"] = config.admin_secret
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


# Optional /oauth/token parameters, sent only when set. Covers refresh_token,
# client_credentials (RFC 6749 §4.4), RFC 7523 client_assertion, and RFC 8693
# token exchange (+ RFC 8707 resource).
_TOKEN_OPTIONAL_PARAMS = (
    "refresh_token",
    "client_secret",
    "scope",
    "client_assertion",
    "client_assertion_type",
    "subject_token",
    "subject_token_type",
    "actor_token",
    "actor_token_type",
    "resource",
)

def build_token_body(client_id: str, req: Any) -> dict[str, str]:
    """Build the /oauth/token form body from a GetTokenRequest.

    Only set parameters are sent. The body MUST be form-encoded on the wire:
    the server reads the RFC 8707 ``resource`` parameter from the POST form
    (to reject repeated values), so a JSON body would drop it.
    """
    grant_type = req.grant_type or "authorization_code"
    if grant_type == "refresh_token" and not (req.refresh_token and req.refresh_token.strip()):
        raise ValueError("refresh_token is required for refresh_token grant")
    if grant_type == GRANT_TYPE_TOKEN_EXCHANGE and not (
        req.subject_token and req.subject_token.strip()
    ):
        raise ValueError("subject_token is required for token exchange grant")
    body: dict[str, str] = {"client_id": client_id, "grant_type": grant_type}
    if grant_type == "authorization_code":
        body["code"] = req.code or ""
        body["code_verifier"] = req.code_verifier or ""
    for key in _TOKEN_OPTIONAL_PARAMS:
        value = getattr(req, key)
        if value:
            body[key] = value
    return body


def prepare_http(
    config: ClientConfig,
    spec: Any,
    data: dict[str, Any] | None,
    headers: dict[str, str] | None,
) -> tuple[RequestSpec, str, str | None]:
    """Build the RequestSpec for graphql/rest from a MethodSpec + data.

    Returns ``(request_spec, kind, unwrap)`` where ``kind`` is ``"graphql"`` or
    ``"rest"`` (selects the response parser) and ``unwrap`` is the response
    field to extract (graphql field name, or the rest wrapper key).
    """
    full_headers = build_headers(config, headers)
    if config.protocol == "rest":
        body = None if spec.rest_method == "GET" else (data or {})
        req = build_rest_request(
            config.authorizer_url, spec.rest_method, spec.rest_path, body, full_headers
        )
        return req, "rest", spec.rest_unwrap
    # gql_flat_vars: a handful of GraphQL fields (webauthn_* ceremonies) take
    # top-level scalar args instead of a single ``params: X`` input object, so
    # the query variables ARE the data dict, not {"data": data}.
    if spec.gql_flat_vars:
        variables = data or None
    else:
        variables = {"data": data} if data is not None else None
    req = build_graphql_request(config.authorizer_url, spec.gql_query, variables, full_headers)
    return req, "graphql", spec.gql_field


def build_rest_request(
    authorizer_url: str,
    method: str,
    path: str,
    body: dict[str, Any] | None,
    headers: dict[str, str],
) -> RequestSpec:
    """Build a REST request for a proto google.api.http annotated path."""
    return RequestSpec(method, f"{authorizer_url}{path}", headers, body or {})


def raise_for_rest_error(status: int, body: bytes) -> None:
    """Raise AuthorizerError for a failed grpc-gateway REST response (>= 400).

    Errors surface in a ``{"message": ..., "code": ...}`` shape; this runs before
    protojson parsing because the error body is not a valid proto response.
    """
    if status < 400:
        return
    decoded = _decode(body)
    message = f"HTTP {status}"
    if isinstance(decoded, dict):
        message = str(decoded.get("message") or decoded.get("error") or message)
    text = body.decode("utf-8", "replace") if not isinstance(decoded, dict) else ""
    raise AuthorizerError(f"{message}: {text}".strip().rstrip(":").strip(), status=status)


def parse_rest_response(
    status: int, body: bytes, unwrap: str | None
) -> dict[str, Any] | None:
    """Parse a REST gateway JSON response with plain JSON (no proto types).

    Retained for REST methods that have no proto response message. The proto-typed
    path (most methods) uses ``_grpc_transport.parse_rest_proto`` instead so int64
    strings and field names map correctly.
    """
    raise_for_rest_error(status, body)
    decoded = _decode(body)
    if not isinstance(decoded, dict):
        return None
    if unwrap is None:
        return decoded
    inner = decoded.get(unwrap)
    return inner if isinstance(inner, dict) else None


def parse_rest(
    spec: Any, status: int, body: bytes, unwrap: str | None, admin: bool
) -> dict[str, Any] | None:
    """Parse a REST response for a MethodSpec.

    Proto-backed REST methods (``spec.grpc_method`` set) are parsed with protojson
    so int64/uint64 strings and field names map correctly; methods without a proto
    response fall back to plain JSON.
    """
    raise_for_rest_error(status, body)
    if spec.grpc_method:
        from ._proto import parse_rest_proto

        result = parse_rest_proto(body, spec.grpc_method, admin, unwrap)
        return result if isinstance(result, dict) else None
    return parse_rest_response(status, body, unwrap)


def unsupported_protocol_error(method: str, protocol: str, supported: tuple[str, ...]) -> Any:
    """Build a clear AuthorizerError for a method called on an unsupported protocol."""
    alts = " or ".join(p for p in supported) if supported else "(none)"
    return AuthorizerError(
        f"{method} is not available over {protocol}; use {alts}"
    )


def _decode(body: bytes) -> Any:
    if not body:
        return None
    try:
        return _json.loads(body)
    except ValueError:
        return None


def _raise_for_graphql_errors(status: int, decoded: Any, body: bytes) -> None:
    """Raise AuthorizerError if *decoded* contains a GraphQL errors array or status >= 400."""
    if isinstance(decoded, dict):
        errors = decoded.get("errors")
        if errors:
            message = "request failed"
            if isinstance(errors, list) and errors:
                first = errors[0]
                if isinstance(first, dict) and first.get("message"):
                    message = str(first["message"])
            elif isinstance(errors, str) and errors:
                message = errors
            raise AuthorizerError(
                message,
                errors=errors if isinstance(errors, list) else [errors],
                status=status,
            )
    if status >= 400:
        text = body.decode("utf-8", "replace") if body else ""
        raise AuthorizerError(f"HTTP {status}: {text}".strip(), status=status)


def parse_graphql_response(status: int, body: bytes, field_name: str) -> dict[str, Any] | None:
    """Return ``data[field_name]`` or raise AuthorizerError.

    Mirrors authorizer-go: a non-empty ``errors`` array is an API error; a
    >=400 status with no ``errors`` array (CSRF 403, proxy page) is also an error.
    """
    decoded = _decode(body)
    _raise_for_graphql_errors(status, decoded, body)
    if isinstance(decoded, dict):
        data = decoded.get("data")
        if isinstance(data, dict):
            return data.get(field_name)
    return None


def parse_graphql_data(status: int, body: bytes) -> dict[str, Any]:
    """Return the whole GraphQL ``data`` object (or {}), raising on errors.

    Behaves like :func:`parse_graphql_response` but returns the full ``data``
    dict instead of a single named field.  Intended for :meth:`graphql_query`.
    """
    decoded = _decode(body)
    _raise_for_graphql_errors(status, decoded, body)
    if isinstance(decoded, dict):
        data = decoded.get("data")
        if isinstance(data, dict):
            return data
    return {}


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
