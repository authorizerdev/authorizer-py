"""Protobuf (protojson) helpers shared by the REST and gRPC transports.

Only depends on ``protobuf`` + the vendored ``_pb2`` modules — NOT ``grpcio``.
The REST protocol uses this to parse grpc-gateway JSON correctly (int64/uint64
serialize as STRINGS and payloads are wrapped in a single proto field), reusing
the same message<->dict mapping the gRPC transport applies to proto messages.
"""

from __future__ import annotations

from typing import Any


def _load_pb2() -> tuple[Any, Any]:
    """Import the vendored proto message modules (admin + public)."""
    from ._grpc.authorizer.v1 import admin_pb2, authorizer_pb2

    return admin_pb2, authorizer_pb2


def _response_message_cls(grpc_method: str, admin: bool) -> Any:
    """Resolve the proto *response* message class for an RPC by its method name.

    Uses the gRPC service descriptor as the source of truth for each RPC's
    output type (so REST and gRPC agree on shapes).
    """
    from google.protobuf import message_factory

    admin_pb2, authorizer_pb2 = _load_pb2()
    fd = (admin_pb2 if admin else authorizer_pb2).DESCRIPTOR
    svc_name = "AuthorizerAdminService" if admin else "AuthorizerService"
    method = fd.services_by_name[svc_name].methods_by_name[grpc_method]
    return message_factory.GetMessageClass(method.output_type)


def parse_rest_proto(body: bytes, grpc_method: str, admin: bool, unwrap: str | None) -> Any:
    """Parse a grpc-gateway REST body via protojson, then map to the SDK dict."""
    from google.protobuf import json_format

    msg_cls = _response_message_cls(grpc_method, admin)
    msg = json_format.Parse(body, msg_cls(), ignore_unknown_fields=True)
    return unwrap_field(message_to_dict(msg), unwrap)


def build_message(message_cls: Any, payload: dict[str, Any]) -> Any:
    """Convert a snake_case dict into a proto message (ignoring unknown keys).

    Flat free-form maps (``app_data``, ``headers``, ``claims`` — the GraphQL
    ``Map`` scalar) are wrapped into the proto AppData shape ``{"value": {...}}``
    so callers pass the same flat dict regardless of protocol.
    """
    from google.protobuf.json_format import ParseDict

    msg = message_cls()
    return ParseDict(_wrap(payload, msg.DESCRIPTOR), msg, ignore_unknown_fields=True)


def _wrap(value: Any, descriptor: Any) -> Any:
    from google.protobuf.descriptor import FieldDescriptor

    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    fields = {f.name: f for f in descriptor.fields}
    for key, val in value.items():
        field = fields.get(key)
        if field is None or field.type != FieldDescriptor.TYPE_MESSAGE:
            out[key] = val
            continue
        if field.message_type.full_name == "authorizer.v1.AppData":
            # SDK contract: free-form maps are flat; wrap into the proto AppData.
            out[key] = {"value": val} if isinstance(val, dict) else val
        elif isinstance(val, list):
            out[key] = [_wrap(v, field.message_type) for v in val]
        else:
            out[key] = _wrap(val, field.message_type)
    return out


def message_to_dict(message: Any) -> dict[str, Any]:
    """Convert a proto message to a snake_case dict matching the GraphQL/REST shape.

    Two proto-JSON quirks are normalized so the SDK dataclasses see the same
    shape regardless of protocol:

    - int64 fields serialize as strings -> coerced back to ``int``.
    - AppData wraps a free-form map as ``{"value": {...}}`` -> flattened to the
      inner map (matching the GraphQL ``Map`` scalar).
    """
    from google.protobuf.json_format import MessageToDict

    raw = MessageToDict(
        message,
        preserving_proto_field_name=True,
        always_print_fields_with_no_presence=True,
    )
    return _normalize(raw, message.DESCRIPTOR)  # type: ignore[no-any-return]


def unwrap_field(payload: dict[str, Any], field: str | None) -> dict[str, Any] | None:
    if field is None:
        return payload
    inner = payload.get(field)
    return inner if isinstance(inner, dict) else None


def _normalize(value: Any, descriptor: Any) -> Any:
    if not isinstance(value, dict):
        return value
    # AppData: {"value": <struct>} -> <struct> (the flat GraphQL Map).
    if descriptor.full_name == "authorizer.v1.AppData":
        return value.get("value")
    out: dict[str, Any] = {}
    fields = {f.name: f for f in descriptor.fields}
    for key, val in value.items():
        field = fields.get(key)
        if field is None:
            out[key] = val
            continue
        out[key] = _normalize_field(val, field)
    return out


def _normalize_field(val: Any, field: Any) -> Any:
    from google.protobuf.descriptor import FieldDescriptor

    int_types = {
        FieldDescriptor.TYPE_INT64,
        FieldDescriptor.TYPE_UINT64,
        FieldDescriptor.TYPE_SINT64,
        FieldDescriptor.TYPE_FIXED64,
        FieldDescriptor.TYPE_SFIXED64,
    }
    if isinstance(val, list):
        if field.type == FieldDescriptor.TYPE_MESSAGE:
            return [_normalize(v, field.message_type) for v in val]
        if field.type in int_types:
            return [_coerce_int(v) for v in val]
        return val
    if field.type == FieldDescriptor.TYPE_MESSAGE:
        return _normalize(val, field.message_type)
    if field.type in int_types:
        return _coerce_int(val)
    return val


def _coerce_int(val: Any) -> Any:
    if isinstance(val, str):
        try:
            return int(val)
        except ValueError:
            return val
    return val
