"""Asynchronous Authorizer client."""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from . import _queries as q
from . import types as t
from ._core import (
    ClientConfig,
    RequestSpec,
    build_graphql_request,
    build_headers,
    build_oauth_request,
    parse_graphql_data,
    parse_graphql_response,
    parse_oauth_response,
)
from .exceptions import AuthorizerConnectionError


class AsyncAuthorizerClient:
    """Asynchronous client for an Authorizer instance."""

    def __init__(
        self,
        client_id: str,
        authorizer_url: str,
        redirect_url: str = "",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        if not client_id or not client_id.strip():
            raise ValueError("client_id is required")
        if not authorizer_url or not authorizer_url.strip():
            raise ValueError("authorizer_url is required")
        self._config = ClientConfig(
            client_id=client_id,
            authorizer_url=authorizer_url.strip().rstrip("/"),
            redirect_url=redirect_url.strip().rstrip("/"),
            extra_headers=dict(extra_headers or {}),
        )
        self._http = httpx.AsyncClient()

    # -- lifecycle -------------------------------------------------------- #
    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncAuthorizerClient:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.aclose()

    # -- low-level send --------------------------------------------------- #
    async def _send(self, spec: RequestSpec) -> httpx.Response:
        try:
            return await self._http.request(
                spec.method, spec.url, json=spec.json, headers=spec.headers
            )
        except httpx.HTTPError as e:  # network/transport failure
            raise AuthorizerConnectionError(str(e)) from e

    async def _graphql(
        self,
        query: str,
        field_name: str,
        variables: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        spec = build_graphql_request(
            self._config.authorizer_url, query, variables, build_headers(self._config, headers)
        )
        res = await self._send(spec)
        return parse_graphql_response(res.status_code, res.content, field_name)

    async def _oauth(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        spec = build_oauth_request(
            self._config.authorizer_url, path, body, build_headers(self._config, None)
        )
        res = await self._send(spec)
        return parse_oauth_response(res.status_code, res.content)

    # -- public auth flows ----------------------------------------------- #
    async def login(self, req: t.LoginRequest) -> t.AuthToken:
        res = await self._graphql(q.LOGIN, "login", {"data": req.to_dict()})
        return t.AuthToken.from_dict(res or {})

    async def signup(self, req: t.SignUpRequest) -> t.AuthToken:
        res = await self._graphql(q.SIGNUP, "signup", {"data": req.to_dict()})
        return t.AuthToken.from_dict(res or {})

    async def magic_link_login(self, req: t.MagicLinkLoginRequest) -> t.GenericResponse:
        if not req.redirect_uri:
            req.redirect_uri = self._config.redirect_url or None
        res = await self._graphql(q.MAGIC_LINK_LOGIN, "magic_link_login", {"data": req.to_dict()})
        return t.GenericResponse.from_dict(res or {})

    async def verify_otp(self, req: t.VerifyOTPRequest) -> t.AuthToken:
        res = await self._graphql(q.VERIFY_OTP, "verify_otp", {"data": req.to_dict()})
        return t.AuthToken.from_dict(res or {})

    async def verify_email(self, req: t.VerifyEmailRequest) -> t.AuthToken:
        res = await self._graphql(q.VERIFY_EMAIL, "verify_email", {"data": req.to_dict()})
        return t.AuthToken.from_dict(res or {})

    async def resend_otp(self, req: t.ResendOTPRequest) -> t.GenericResponse:
        res = await self._graphql(q.RESEND_OTP, "resend_otp", {"data": req.to_dict()})
        return t.GenericResponse.from_dict(res or {})

    async def resend_verify_email(self, req: t.ResendVerifyEmailRequest) -> t.GenericResponse:
        res = await self._graphql(
            q.RESEND_VERIFY_EMAIL, "resend_verify_email", {"data": req.to_dict()}
        )
        return t.GenericResponse.from_dict(res or {})

    async def forgot_password(self, req: t.ForgotPasswordRequest) -> t.ForgotPasswordResponse:
        if not req.redirect_uri:
            req.redirect_uri = self._config.redirect_url or None
        res = await self._graphql(q.FORGOT_PASSWORD, "forgot_password", {"data": req.to_dict()})
        return t.ForgotPasswordResponse.from_dict(res or {})

    async def reset_password(self, req: t.ResetPasswordRequest) -> t.GenericResponse:
        res = await self._graphql(q.RESET_PASSWORD, "reset_password", {"data": req.to_dict()})
        return t.GenericResponse.from_dict(res or {})

    async def validate_jwt_token(
        self, req: t.ValidateJWTTokenRequest
    ) -> t.ValidateJWTTokenResponse:
        res = await self._graphql(
            q.VALIDATE_JWT_TOKEN, "validate_jwt_token", {"data": req.to_dict()}
        )
        return t.ValidateJWTTokenResponse.from_dict(res or {})

    async def validate_session(self, req: t.ValidateSessionRequest) -> t.ValidateSessionResponse:
        res = await self._graphql(
            q.VALIDATE_SESSION, "validate_session", {"data": req.to_dict()}
        )
        return t.ValidateSessionResponse.from_dict(res or {})

    async def get_meta_data(self) -> t.MetaData:
        res = await self._graphql(q.META, "meta")
        return t.MetaData.from_dict(res or {})

    # -- authenticated (credential headers) ------------------------------ #
    async def get_session(
        self, req: t.SessionQueryRequest | None = None, headers: dict[str, str] | None = None
    ) -> t.AuthToken:
        variables = {"data": req.to_dict()} if req is not None else None
        res = await self._graphql(q.SESSION, "session", variables, headers)
        return t.AuthToken.from_dict(res or {})

    async def get_profile(self, headers: dict[str, str] | None = None) -> t.User:
        res = await self._graphql(q.PROFILE, "profile", None, headers)
        return t.User.from_dict(res or {})

    async def update_profile(
        self, req: t.UpdateProfileRequest, headers: dict[str, str] | None = None
    ) -> t.GenericResponse:
        res = await self._graphql(
            q.UPDATE_PROFILE, "update_profile", {"data": req.to_dict()}, headers
        )
        return t.GenericResponse.from_dict(res or {})

    async def logout(self, headers: dict[str, str] | None = None) -> t.GenericResponse:
        res = await self._graphql(q.LOGOUT, "logout", None, headers)
        return t.GenericResponse.from_dict(res or {})

    async def deactivate_account(self, headers: dict[str, str] | None = None) -> t.GenericResponse:
        res = await self._graphql(q.DEACTIVATE_ACCOUNT, "deactivate_account", None, headers)
        return t.GenericResponse.from_dict(res or {})

    async def check_permissions(
        self, req: t.CheckPermissionsRequest, headers: dict[str, str] | None = None
    ) -> t.CheckPermissionsResponse:
        res = await self._graphql(
            q.CHECK_PERMISSIONS, "check_permissions", {"data": req.to_dict()}, headers
        )
        return t.CheckPermissionsResponse.from_dict(res or {})

    async def list_permissions(
        self, req: t.ListPermissionsRequest, headers: dict[str, str] | None = None
    ) -> t.ListPermissionsResponse:
        res = await self._graphql(
            q.LIST_PERMISSIONS, "list_permissions", {"data": req.to_dict()}, headers
        )
        return t.ListPermissionsResponse.from_dict(res or {})

    # -- OAuth REST ------------------------------------------------------- #
    async def get_token(self, req: t.GetTokenRequest) -> t.GetTokenResponse:
        grant_type = req.grant_type or "authorization_code"
        if grant_type == "refresh_token" and not (req.refresh_token and req.refresh_token.strip()):
            raise ValueError("refresh_token is required for refresh_token grant")
        body: dict[str, Any] = {
            "client_id": self._config.client_id,
            "code": req.code or "",
            "code_verifier": req.code_verifier or "",
            "grant_type": grant_type,
            "refresh_token": req.refresh_token or "",
        }
        return t.GetTokenResponse.from_dict(await self._oauth("/oauth/token", body))

    async def revoke_token(self, req: t.RevokeTokenRequest) -> t.GenericResponse:
        if not req.refresh_token or not req.refresh_token.strip():
            raise ValueError("refresh_token is required")
        body: dict[str, Any] = {
            "refresh_token": req.refresh_token,
            "client_id": self._config.client_id,
        }
        return t.GenericResponse.from_dict(await self._oauth("/oauth/revoke", body))

    # -- escape hatch ----------------------------------------------------- #
    async def graphql_query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        spec = build_graphql_request(
            self._config.authorizer_url, query, variables, build_headers(self._config, headers)
        )
        res = await self._send(spec)
        return parse_graphql_data(res.status_code, res.content)
