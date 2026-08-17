"""I/O-free request building and response parsing shared by both clients."""

from __future__ import annotations

import http.cookiejar as _cookiejar
import json as _json
from dataclasses import dataclass, field
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


class _LoopbackCookieJar(_cookiejar.CookieJar):
    """Cookie jar that keeps loopback cookies usable, the way browsers do.

    Server >= 2.4.0 has MFA on by default: signup/login withhold the access token
    and start an MFA session identified ONLY by the ``mfa_session`` cookie, so
    :meth:`~authorizer.client.AuthorizerClient.skip_mfa_setup` and the
    ``*_mfa_setup`` calls depend on that cookie going back out. Two
    :mod:`http.cookiejar` rules silently drop it against a local server:

    * ``Secure`` cookies are never sent to an ``http://`` URL, but the server sets
      ``Secure`` by default (``--app-cookie-secure``) even when served over http;
    * ``eff_request_host`` derives ``localhost.local`` for a dotless host, which
      never domain-matches the ``Domain=localhost`` cookie the server sets.

    Browsers (and hence the login UI) send the cookie in both cases: W3C secure
    contexts treat loopback as a trustworthy origin. The fix normalises the stored
    cookie rather than installing a :class:`~http.cookiejar.CookiePolicy` because
    httpx rebuilds the outgoing jar with the default policy on every request
    (``BaseClient._merge_cookies``), which discards any custom policy. Non-loopback
    cookies are untouched.
    """

    def set_cookie(self, cookie: Any) -> None:
        host = (cookie.domain or "").lstrip(".").lower()
        if _is_loopback_host(host):
            cookie.secure = False
            if "." not in host:
                cookie.domain = f".{host}.local"
        super().set_cookie(cookie)


def _request_host(request: Any) -> str:
    """Host of an outgoing request, without the port.

    http.cookiejar.request_host does exactly this, but it is absent from
    typeshed's public stubs, so calling it fails `mypy src`. urlsplit is the
    documented equivalent and behaves identically for the URLs httpx builds.
    """
    return (_urlsplit(request.get_full_url()).hostname or "").lower()


def _is_loopback_host(host: str) -> bool:
    host = (host or "").lstrip(".").lower()
    return host in ("localhost", "127.0.0.1", "::1") or host.endswith(".localhost")


class _LoopbackCookiePolicy(_cookiejar.DefaultCookiePolicy):
    """Accept a loopback ``Set-Cookie`` that the default policy discards.

    Normalising in :meth:`_LoopbackCookieJar.set_cookie` is not enough on its
    own, and the reason is a layering detail worth stating: intake goes through
    ``extract_cookies``, which asks the POLICY (``set_ok``) whether to keep the
    cookie and only calls ``set_cookie`` if it says yes. On Python 3.9 and 3.10
    the default policy rejects ``Domain=localhost`` for an ``http://localhost``
    request, so the jar's ``set_cookie`` override never ran and the MFA session
    was dropped before it could be normalised — the fix silently did nothing on
    exactly the two oldest supported interpreters, which is why the regression
    test for it failed there and passed on 3.11+.

    Only the DOMAIN check is relaxed, and only for loopback. Every other rule —
    path, port, version, third-party blocking — still runs, and a non-loopback
    cookie takes the unmodified default path.
    """

    def set_ok(self, cookie: Any, request: Any) -> bool:
        # Gate on the REQUEST host, never on the cookie's own Domain. Trusting
        # the cookie alone lets ANY origin store a localhost-scoped cookie —
        # https://evil.example.com replying `Set-Cookie: mfa_session=…;
        # Domain=localhost` would be accepted and then sent to the local
        # Authorizer, which is session fixation into the MFA session. Verified
        # by test_remote_host_cannot_plant_a_loopback_cookie.
        req_host = _request_host(request)
        if _is_loopback_host(req_host) and _is_loopback_host(
            getattr(cookie, "domain", "") or req_host
        ):
            return self.set_ok_verifiability(cookie, request) and self.set_ok_path(
                cookie, request
            )
        return bool(super().set_ok(cookie, request))


def new_cookie_jar() -> _cookiejar.CookieJar:
    """Cookie jar for the SDK's httpx client (see :class:`_LoopbackCookieJar`)."""
    return _LoopbackCookieJar(policy=_LoopbackCookiePolicy())


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
