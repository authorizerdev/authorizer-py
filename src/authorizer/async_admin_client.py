"""Asynchronous Authorizer admin client (parity with AuthorizerAdminClient)."""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from . import _dispatch as d
from . import types as t
from ._core import (
    PROTOCOLS,
    ClientConfig,
    RequestSpec,
    parse_graphql_response,
    parse_rest,
    prepare_http,
    unsupported_protocol_error,
)
from ._dispatch import MethodSpec
from .exceptions import AuthorizerConnectionError


class AsyncAuthorizerAdminClient:
    """Asynchronous client for Authorizer's super-admin-only API surface."""

    _ADMIN = True

    def __init__(
        self,
        authorizer_url: str,
        admin_secret: str,
        extra_headers: dict[str, str] | None = None,
        protocol: str = "graphql",
        grpc_endpoint: str = "",
    ) -> None:
        if not authorizer_url or not authorizer_url.strip():
            raise ValueError("authorizer_url is required")
        if not admin_secret or not admin_secret.strip():
            raise ValueError("admin_secret is required")
        if protocol not in PROTOCOLS:
            raise ValueError(f"protocol must be one of {PROTOCOLS}, got {protocol!r}")
        self._config = ClientConfig(
            client_id="",
            authorizer_url=authorizer_url.strip().rstrip("/"),
            redirect_url="",
            extra_headers=dict(extra_headers or {}),
            protocol=protocol,
            admin_secret=admin_secret,
            grpc_endpoint=grpc_endpoint.strip(),
        )
        self._http = httpx.AsyncClient()
        self._channel: Any = None

    # -- lifecycle -------------------------------------------------------- #
    async def aclose(self) -> None:
        await self._http.aclose()
        if self._channel is not None:
            await self._channel.close()
            self._channel = None

    async def __aenter__(self) -> AsyncAuthorizerAdminClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # -- dispatch --------------------------------------------------------- #
    async def _send(self, spec: RequestSpec) -> httpx.Response:
        try:
            return await self._http.request(
                spec.method, spec.url, json=spec.json, headers=spec.headers
            )
        except httpx.HTTPError as e:
            raise AuthorizerConnectionError(str(e)) from e

    async def _invoke(
        self,
        method: str,
        spec: MethodSpec,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        proto = self._config.protocol
        if proto not in spec.protocols:
            raise unsupported_protocol_error(method, proto, spec.protocols)
        if proto == "grpc":
            from . import _grpc_transport as g

            if self._channel is None:
                self._channel = g.make_async_channel(
                    self._config.authorizer_url, self._config.grpc_endpoint
                )
            md = g.grpc_metadata(self._config, headers)
            return await g.grpc_acall(self._channel, spec, data, md, self._ADMIN)
        req, kind, unwrap = prepare_http(self._config, spec, data, headers)
        res = await self._send(req)
        if kind == "rest":
            return parse_rest(spec, res.status_code, res.content, unwrap, self._ADMIN)
        return parse_graphql_response(res.status_code, res.content, unwrap or "")

    # -- admin auth + meta ------------------------------------------------ #
    async def admin_login(self, req: t.AdminLoginRequest) -> t.GenericResponse:
        res = await self._invoke("admin_login", d.ADMIN["admin_login"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def admin_logout(self) -> t.GenericResponse:
        res = await self._invoke("admin_logout", d.ADMIN["admin_logout"], None)
        return t.GenericResponse.from_dict(res or {})

    async def admin_session(self) -> t.GenericResponse:
        res = await self._invoke("admin_session", d.ADMIN["admin_session"], None)
        return t.GenericResponse.from_dict(res or {})

    async def admin_meta(self) -> t.AdminMeta:
        res = await self._invoke("admin_meta", d.ADMIN["admin_meta"], None)
        return t.AdminMeta.from_dict(res or {})

    async def admin_signup(self, req: t.AdminSignupRequest) -> t.GenericResponse:
        res = await self._invoke("admin_signup", d.ADMIN["admin_signup"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def update_env(self, env: dict[str, Any]) -> t.GenericResponse:
        res = await self._invoke("update_env", d.ADMIN["update_env"], env)
        return t.GenericResponse.from_dict(res or {})

    async def generate_jwt_keys(
        self, req: t.GenerateJWTKeysRequest
    ) -> t.GenerateJWTKeysResponse:
        res = await self._invoke("generate_jwt_keys", d.ADMIN["generate_jwt_keys"], req.to_dict())
        return t.GenerateJWTKeysResponse.from_dict(res or {})

    # -- users ------------------------------------------------------------ #
    async def users(self, req: t.PaginatedRequest | None = None) -> t.UsersResponse:
        res = await self._invoke("users", d.ADMIN["users"], req.to_dict() if req else None)
        return t.UsersResponse.from_dict(res or {})

    async def user(self, req: t.GetUserRequest) -> t.User:
        res = await self._invoke("user", d.ADMIN["user"], req.to_dict())
        return t.User.from_dict(res or {})

    async def update_user(self, req: t.UpdateUserRequest) -> t.User:
        res = await self._invoke("update_user", d.ADMIN["update_user"], req.to_dict())
        return t.User.from_dict(res or {})

    async def delete_user(self, req: t.DeleteUserRequest) -> t.GenericResponse:
        """Destructive: permanently deletes the user and associated OTP/verification data."""
        res = await self._invoke("delete_user", d.ADMIN["delete_user"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def verification_requests(
        self, req: t.PaginatedRequest | None = None
    ) -> t.VerificationRequestsResponse:
        res = await self._invoke(
            "verification_requests", d.ADMIN["verification_requests"],
            req.to_dict() if req else None,
        )
        return t.VerificationRequestsResponse.from_dict(res or {})

    # -- access ----------------------------------------------------------- #
    async def revoke_access(self, req: t.UpdateAccessRequest) -> t.GenericResponse:
        res = await self._invoke("revoke_access", d.ADMIN["revoke_access"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def enable_access(self, req: t.UpdateAccessRequest) -> t.GenericResponse:
        res = await self._invoke("enable_access", d.ADMIN["enable_access"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def invite_members(self, req: t.InviteMembersRequest) -> t.InviteMembersResponse:
        res = await self._invoke("invite_members", d.ADMIN["invite_members"], req.to_dict())
        return t.InviteMembersResponse.from_dict(res or {})

    # -- webhooks --------------------------------------------------------- #
    async def add_webhook(self, req: t.AddWebhookRequest) -> t.GenericResponse:
        res = await self._invoke("add_webhook", d.ADMIN["add_webhook"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def update_webhook(self, req: t.UpdateWebhookRequest) -> t.GenericResponse:
        res = await self._invoke("update_webhook", d.ADMIN["update_webhook"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def delete_webhook(self, req: t.WebhookRequest) -> t.GenericResponse:
        """Destructive: permanently deletes the webhook."""
        res = await self._invoke("delete_webhook", d.ADMIN["delete_webhook"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def get_webhook(self, req: t.WebhookRequest) -> t.Webhook:
        res = await self._invoke("get_webhook", d.ADMIN["get_webhook"], req.to_dict())
        return t.Webhook.from_dict(res or {})

    async def webhooks(self, req: t.PaginatedRequest | None = None) -> t.WebhooksResponse:
        res = await self._invoke("webhooks", d.ADMIN["webhooks"], req.to_dict() if req else None)
        return t.WebhooksResponse.from_dict(res or {})

    async def webhook_logs(
        self, req: t.ListWebhookLogRequest | None = None
    ) -> t.WebhookLogsResponse:
        res = await self._invoke(
            "webhook_logs", d.ADMIN["webhook_logs"], req.to_dict() if req else None
        )
        return t.WebhookLogsResponse.from_dict(res or {})

    async def test_endpoint(self, req: t.TestEndpointRequest) -> t.TestEndpointResponse:
        res = await self._invoke("test_endpoint", d.ADMIN["test_endpoint"], req.to_dict())
        return t.TestEndpointResponse.from_dict(res or {})

    # -- email templates -------------------------------------------------- #
    async def add_email_template(self, req: t.AddEmailTemplateRequest) -> t.GenericResponse:
        res = await self._invoke("add_email_template", d.ADMIN["add_email_template"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def update_email_template(self, req: t.UpdateEmailTemplateRequest) -> t.GenericResponse:
        res = await self._invoke(
            "update_email_template", d.ADMIN["update_email_template"], req.to_dict()
        )
        return t.GenericResponse.from_dict(res or {})

    async def delete_email_template(self, req: t.DeleteEmailTemplateRequest) -> t.GenericResponse:
        """Destructive: permanently deletes the email template."""
        res = await self._invoke(
            "delete_email_template", d.ADMIN["delete_email_template"], req.to_dict()
        )
        return t.GenericResponse.from_dict(res or {})

    async def email_templates(
        self, req: t.PaginatedRequest | None = None
    ) -> t.EmailTemplatesResponse:
        res = await self._invoke(
            "email_templates", d.ADMIN["email_templates"], req.to_dict() if req else None
        )
        return t.EmailTemplatesResponse.from_dict(res or {})

    # -- audit ------------------------------------------------------------ #
    async def audit_logs(self, req: t.ListAuditLogRequest | None = None) -> t.AuditLogsResponse:
        res = await self._invoke(
            "audit_logs", d.ADMIN["audit_logs"], req.to_dict() if req else None
        )
        return t.AuditLogsResponse.from_dict(res or {})

    # -- FGA -------------------------------------------------------------- #
    async def fga_get_model(self) -> t.FgaModel:
        res = await self._invoke("fga_get_model", d.ADMIN["fga_get_model"], None)
        return t.FgaModel.from_dict(res or {})

    async def fga_write_model(self, req: t.FgaWriteModelRequest) -> t.FgaModel:
        """Destructive: replaces the active fine-grained authorization model."""
        res = await self._invoke("fga_write_model", d.ADMIN["fga_write_model"], req.to_dict())
        return t.FgaModel.from_dict(res or {})

    async def fga_write_tuples(self, req: t.FgaWriteTuplesRequest) -> t.GenericResponse:
        res = await self._invoke("fga_write_tuples", d.ADMIN["fga_write_tuples"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def fga_delete_tuples(self, req: t.FgaWriteTuplesRequest) -> t.GenericResponse:
        """Destructive: removes the given relationship tuples."""
        res = await self._invoke("fga_delete_tuples", d.ADMIN["fga_delete_tuples"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    async def fga_read_tuples(self, req: t.FgaReadTuplesRequest) -> t.FgaReadTuplesResponse:
        res = await self._invoke("fga_read_tuples", d.ADMIN["fga_read_tuples"], req.to_dict())
        return t.FgaReadTuplesResponse.from_dict(res or {})

    async def fga_list_users(self, req: t.FgaListUsersRequest) -> t.FgaListUsersResponse:
        res = await self._invoke("fga_list_users", d.ADMIN["fga_list_users"], req.to_dict())
        return t.FgaListUsersResponse.from_dict(res or {})

    async def fga_expand(self, req: t.FgaExpandRequest) -> t.FgaExpandResponse:
        res = await self._invoke("fga_expand", d.ADMIN["fga_expand"], req.to_dict())
        return t.FgaExpandResponse.from_dict(res or {})

    async def fga_reset(self) -> t.GenericResponse:
        """Destructive: deletes the entire fine-grained authorization store."""
        res = await self._invoke("fga_reset", d.ADMIN["fga_reset"], None)
        return t.GenericResponse.from_dict(res or {})
