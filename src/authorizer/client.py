"""Synchronous Authorizer client."""

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
    build_graphql_request,
    build_headers,
    build_oauth_request,
    build_token_body,
    parse_graphql_data,
    parse_graphql_response,
    parse_oauth_response,
    parse_rest,
    prepare_http,
    unsupported_protocol_error,
)
from ._dispatch import MethodSpec
from .exceptions import AuthorizerConnectionError


class AuthorizerClient:
    """Synchronous client for an Authorizer instance."""

    _ADMIN = False

    def __init__(
        self,
        client_id: str,
        authorizer_url: str,
        redirect_url: str = "",
        extra_headers: dict[str, str] | None = None,
        protocol: str = "graphql",
        grpc_endpoint: str = "",
    ) -> None:
        if not client_id or not client_id.strip():
            raise ValueError("client_id is required")
        if not authorizer_url or not authorizer_url.strip():
            raise ValueError("authorizer_url is required")
        if protocol not in PROTOCOLS:
            raise ValueError(f"protocol must be one of {PROTOCOLS}, got {protocol!r}")
        self._config = ClientConfig(
            client_id=client_id,
            authorizer_url=authorizer_url.strip().rstrip("/"),
            redirect_url=redirect_url.strip().rstrip("/"),
            extra_headers=dict(extra_headers or {}),
            protocol=protocol,
            grpc_endpoint=grpc_endpoint.strip(),
        )
        self._http = httpx.Client()
        self._channel: Any = None

    # -- lifecycle -------------------------------------------------------- #
    def close(self) -> None:
        self._http.close()
        if self._channel is not None:
            self._channel.close()
            self._channel = None

    def __enter__(self) -> AuthorizerClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- low-level send --------------------------------------------------- #
    def _send(self, spec: RequestSpec) -> httpx.Response:
        try:
            return self._http.request(
                spec.method, spec.url, json=spec.json, headers=spec.headers
            )
        except httpx.HTTPError as e:  # network/transport failure
            raise AuthorizerConnectionError(str(e)) from e

    def _oauth(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        spec = build_oauth_request(
            self._config.authorizer_url, path, body, build_headers(self._config, None)
        )
        res = self._send(spec)
        return parse_oauth_response(res.status_code, res.content)

    def _oauth_form(self, path: str, body: dict[str, str]) -> dict[str, Any]:
        """POST an application/x-www-form-urlencoded OAuth request (RFC 6749 §4.1.3)."""
        headers = build_headers(
            self._config, {"Content-Type": "application/x-www-form-urlencoded"}
        )
        try:
            res = self._http.post(
                f"{self._config.authorizer_url}{path}", data=body, headers=headers
            )
        except httpx.HTTPError as e:
            raise AuthorizerConnectionError(str(e)) from e
        return parse_oauth_response(res.status_code, res.content)

    def _invoke(
        self,
        method: str,
        spec: MethodSpec,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        """Dispatch ``method`` over the configured protocol and return a dict."""
        proto = self._config.protocol
        if proto not in spec.protocols:
            raise unsupported_protocol_error(method, proto, spec.protocols)
        if proto == "grpc":
            from . import _grpc_transport as g

            if self._channel is None:
                self._channel = g.make_channel(
                    self._config.authorizer_url, self._config.grpc_endpoint
                )
            md = g.grpc_metadata(self._config, headers)
            return g.grpc_call(self._channel, spec, data, md, self._ADMIN)
        req, kind, unwrap = prepare_http(self._config, spec, data, headers)
        res = self._send(req)
        if kind == "rest":
            return parse_rest(spec, res.status_code, res.content, unwrap, self._ADMIN)
        return parse_graphql_response(res.status_code, res.content, unwrap or "")

    # -- public auth flows ----------------------------------------------- #
    def login(self, req: t.LoginRequest) -> t.AuthToken:
        res = self._invoke("login", d.PUBLIC["login"], req.to_dict())
        return t.AuthToken.from_dict(res or {})

    def signup(self, req: t.SignUpRequest) -> t.AuthToken:
        res = self._invoke("signup", d.PUBLIC["signup"], req.to_dict())
        return t.AuthToken.from_dict(res or {})

    def magic_link_login(self, req: t.MagicLinkLoginRequest) -> t.GenericResponse:
        payload = req.to_dict()
        if not payload.get("redirect_uri") and self._config.redirect_url:
            payload["redirect_uri"] = self._config.redirect_url
        res = self._invoke("magic_link_login", d.PUBLIC["magic_link_login"], payload)
        return t.GenericResponse.from_dict(res or {})

    def verify_otp(self, req: t.VerifyOTPRequest) -> t.AuthToken:
        res = self._invoke("verify_otp", d.PUBLIC["verify_otp"], req.to_dict())
        return t.AuthToken.from_dict(res or {})

    def verify_email(self, req: t.VerifyEmailRequest) -> t.AuthToken:
        res = self._invoke("verify_email", d.PUBLIC["verify_email"], req.to_dict())
        return t.AuthToken.from_dict(res or {})

    def resend_otp(self, req: t.ResendOTPRequest) -> t.GenericResponse:
        res = self._invoke("resend_otp", d.PUBLIC["resend_otp"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def resend_verify_email(self, req: t.ResendVerifyEmailRequest) -> t.GenericResponse:
        res = self._invoke("resend_verify_email", d.PUBLIC["resend_verify_email"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def forgot_password(self, req: t.ForgotPasswordRequest) -> t.ForgotPasswordResponse:
        payload = req.to_dict()
        if not payload.get("redirect_uri") and self._config.redirect_url:
            payload["redirect_uri"] = self._config.redirect_url
        res = self._invoke("forgot_password", d.PUBLIC["forgot_password"], payload)
        return t.ForgotPasswordResponse.from_dict(res or {})

    def reset_password(self, req: t.ResetPasswordRequest) -> t.GenericResponse:
        res = self._invoke("reset_password", d.PUBLIC["reset_password"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def validate_jwt_token(self, req: t.ValidateJWTTokenRequest) -> t.ValidateJWTTokenResponse:
        res = self._invoke("validate_jwt_token", d.PUBLIC["validate_jwt_token"], req.to_dict())
        return t.ValidateJWTTokenResponse.from_dict(res or {})

    def validate_session(self, req: t.ValidateSessionRequest) -> t.ValidateSessionResponse:
        res = self._invoke("validate_session", d.PUBLIC["validate_session"], req.to_dict())
        return t.ValidateSessionResponse.from_dict(res or {})

    def get_meta_data(self) -> t.MetaData:
        res = self._invoke("meta", d.PUBLIC["meta"], None)
        return t.MetaData.from_dict(res or {})

    # -- authenticated (credential headers) ------------------------------ #
    def get_session(
        self, req: t.SessionQueryRequest | None = None, headers: dict[str, str] | None = None
    ) -> t.AuthToken:
        data = req.to_dict() if req is not None else None
        res = self._invoke("session", d.PUBLIC["session"], data, headers)
        return t.AuthToken.from_dict(res or {})

    def get_profile(self, headers: dict[str, str] | None = None) -> t.User:
        res = self._invoke("profile", d.PUBLIC["profile"], None, headers)
        return t.User.from_dict(res or {})

    def update_profile(
        self, req: t.UpdateProfileRequest, headers: dict[str, str] | None = None
    ) -> t.GenericResponse:
        res = self._invoke("update_profile", d.PUBLIC["update_profile"], req.to_dict(), headers)
        return t.GenericResponse.from_dict(res or {})

    def logout(self, headers: dict[str, str] | None = None) -> t.GenericResponse:
        res = self._invoke("logout", d.PUBLIC["logout"], None, headers)
        return t.GenericResponse.from_dict(res or {})

    def deactivate_account(self, headers: dict[str, str] | None = None) -> t.GenericResponse:
        res = self._invoke("deactivate_account", d.PUBLIC["deactivate_account"], None, headers)
        return t.GenericResponse.from_dict(res or {})

    def check_permissions(
        self, req: t.CheckPermissionsRequest, headers: dict[str, str] | None = None
    ) -> t.CheckPermissionsResponse:
        res = self._invoke(
            "check_permissions", d.PUBLIC["check_permissions"], req.to_dict(), headers
        )
        return t.CheckPermissionsResponse.from_dict(res or {})

    def list_permissions(
        self, req: t.ListPermissionsRequest, headers: dict[str, str] | None = None
    ) -> t.ListPermissionsResponse:
        res = self._invoke(
            "list_permissions", d.PUBLIC["list_permissions"], req.to_dict(), headers
        )
        return t.ListPermissionsResponse.from_dict(res or {})

    # -- OAuth REST ------------------------------------------------------- #
    def get_token(self, req: t.GetTokenRequest) -> t.GetTokenResponse:
        """Exchange credentials for tokens at ``/oauth/token``.

        Supported grants: ``authorization_code`` (default), ``refresh_token``,
        ``client_credentials`` (RFC 6749 §4.4) and RFC 8693 token exchange
        (:data:`types.GRANT_TYPE_TOKEN_EXCHANGE`). The machine grants are for
        trusted server-side code only — never expose ``client_secret``,
        ``client_assertion``, or subject/actor tokens to untrusted code.
        """
        body = build_token_body(self._config.client_id, req)
        return t.GetTokenResponse.from_dict(self._oauth_form("/oauth/token", body))

    def revoke_token(self, req: t.RevokeTokenRequest) -> t.GenericResponse:
        if not req.refresh_token or not req.refresh_token.strip():
            raise ValueError("refresh_token is required")
        body: dict[str, Any] = {
            "refresh_token": req.refresh_token,
            "client_id": self._config.client_id,
        }
        return t.GenericResponse.from_dict(self._oauth("/oauth/revoke", body))

    # -- escape hatch ----------------------------------------------------- #
    def graphql_query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        spec = build_graphql_request(
            self._config.authorizer_url, query, variables, build_headers(self._config, headers)
        )
        res = self._send(spec)
        return parse_graphql_data(res.status_code, res.content)
