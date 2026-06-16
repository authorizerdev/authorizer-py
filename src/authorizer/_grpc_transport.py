"""Lazy gRPC transport for the Authorizer SDK.

grpc + protobuf are optional (the ``grpc`` extra). Everything here imports them
lazily so the SDK works without them when protocol != "grpc".
"""

from __future__ import annotations

from typing import Any
from urllib.parse import urlparse

from ._core import ClientConfig
from ._proto import build_message, message_to_dict, unwrap_field
from .exceptions import AuthorizerError

_MISSING_MSG = (
    "protocol='grpc' requires the optional gRPC dependencies. "
    "Install them with: pip install 'authorizer-py[grpc]'"
)


def _require_grpc() -> Any:
    try:
        import grpc  # noqa: F401
    except ImportError as e:  # pragma: no cover - exercised via tests w/o grpc
        raise AuthorizerError(_MISSING_MSG) from e
    return grpc


# The server's gRPC listener default port (separate from the HTTP port).
GRPC_DEFAULT_PORT = 9091


def _target_and_secure(authorizer_url: str, grpc_endpoint: str = "") -> tuple[str, bool]:
    """Return (host:port, use_tls) for a gRPC channel.

    When ``grpc_endpoint`` is set it is dialed verbatim. Otherwise the host is
    derived from ``authorizer_url`` and port :data:`GRPC_DEFAULT_PORT` is used
    (the server's gRPC listener runs on a separate port, not the HTTP port).
    """
    parsed = urlparse(authorizer_url)
    secure = parsed.scheme == "https"
    if grpc_endpoint:
        return grpc_endpoint, secure
    host = parsed.hostname or "localhost"
    return f"{host}:{GRPC_DEFAULT_PORT}", secure


def grpc_metadata(config: ClientConfig, per_call: dict[str, str] | None) -> list[tuple[str, str]]:
    """Build gRPC metadata mirroring the HTTP identity/admin headers (lowercased)."""
    md: dict[str, str] = {
        "x-authorizer-url": config.authorizer_url,
        "x-authorizer-client-id": config.client_id,
    }
    if config.admin_secret:
        md["x-authorizer-admin-secret"] = config.admin_secret
    for k, v in config.extra_headers.items():
        md[k.lower()] = v
    if per_call:
        for k, v in per_call.items():
            md[k.lower()] = v
    return list(md.items())


def make_channel(authorizer_url: str, grpc_endpoint: str = "") -> Any:
    """Create a synchronous gRPC channel."""
    grpc = _require_grpc()
    target, secure = _target_and_secure(authorizer_url, grpc_endpoint)
    if secure:
        return grpc.secure_channel(target, grpc.ssl_channel_credentials())
    return grpc.insecure_channel(target)


def make_async_channel(authorizer_url: str, grpc_endpoint: str = "") -> Any:
    """Create an asynchronous (grpc.aio) gRPC channel."""
    grpc = _require_grpc()
    target, secure = _target_and_secure(authorizer_url, grpc_endpoint)
    if secure:
        return grpc.aio.secure_channel(target, grpc.ssl_channel_credentials())
    return grpc.aio.insecure_channel(target)


def load_stubs() -> Any:
    """Import the vendored generated stub modules (lazily)."""
    _require_grpc()
    from ._grpc.authorizer.v1 import (
        admin_pb2,
        admin_pb2_grpc,
        authorizer_pb2,
        authorizer_pb2_grpc,
    )

    return admin_pb2, admin_pb2_grpc, authorizer_pb2, authorizer_pb2_grpc


def _resolve(spec: Any, admin: bool) -> tuple[Any, Any, Any]:
    """Return (stub_class, pb2_module, channel-less). Picks admin vs public modules."""
    admin_pb2, admin_pb2_grpc, authorizer_pb2, authorizer_pb2_grpc = load_stubs()
    if admin:
        return admin_pb2_grpc.AuthorizerAdminServiceStub, admin_pb2, None
    return authorizer_pb2_grpc.AuthorizerServiceStub, authorizer_pb2, None


def grpc_call(
    channel: Any,
    spec: Any,
    data: dict[str, Any] | None,
    metadata: list[tuple[str, str]],
    admin: bool,
) -> dict[str, Any] | None:
    """Invoke a unary gRPC method on a synchronous channel and return a dict."""
    grpc = _require_grpc()
    stub_cls, pb2, _ = _resolve(spec, admin)
    stub = stub_cls(channel)
    request = build_message(getattr(pb2, spec.grpc_request), data or {})
    try:
        response = getattr(stub, spec.grpc_method)(request, metadata=metadata)
    except grpc.RpcError as e:  # pragma: no cover - exercised live
        raise AuthorizerError(_rpc_message(e)) from e
    return unwrap_field(message_to_dict(response), spec.grpc_response_unwrap)


async def grpc_acall(
    channel: Any,
    spec: Any,
    data: dict[str, Any] | None,
    metadata: list[tuple[str, str]],
    admin: bool,
) -> dict[str, Any] | None:
    """Invoke a unary gRPC method on a grpc.aio channel and return a dict."""
    grpc = _require_grpc()
    stub_cls, pb2, _ = _resolve(spec, admin)
    stub = stub_cls(channel)
    request = build_message(getattr(pb2, spec.grpc_request), data or {})
    try:
        response = await getattr(stub, spec.grpc_method)(request, metadata=metadata)
    except grpc.RpcError as e:  # pragma: no cover - exercised live
        raise AuthorizerError(_rpc_message(e)) from e
    return unwrap_field(message_to_dict(response), spec.grpc_response_unwrap)


def _rpc_message(e: Any) -> str:
    try:
        return str(e.details() or e.code())
    except Exception:  # pragma: no cover - defensive
        return str(e)
