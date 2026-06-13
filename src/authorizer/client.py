"""Synchronous Authorizer client."""

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
    parse_graphql_response,
    parse_oauth_response,
)
from .exceptions import AuthorizerConnectionError


class AuthorizerClient:
    """Synchronous client for an Authorizer instance."""

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
        self._http = httpx.Client()

    # -- lifecycle -------------------------------------------------------- #
    def close(self) -> None:
        self._http.close()

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

    def _graphql(
        self,
        query: str,
        field_name: str,
        variables: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        spec = build_graphql_request(
            self._config.authorizer_url, query, variables, build_headers(self._config, headers)
        )
        res = self._send(spec)
        return parse_graphql_response(res.status_code, res.content, field_name)

    def _oauth(self, path: str, body: dict[str, Any]) -> dict[str, Any]:
        spec = build_oauth_request(
            self._config.authorizer_url, path, body, build_headers(self._config, None)
        )
        res = self._send(spec)
        return parse_oauth_response(res.status_code, res.content)

    # -- temporary convenience (removed in Task 8) ------------------------ #
    def login_from(self, email: str, password: str) -> t.AuthToken:
        res = self._graphql(q.LOGIN, "login", {"data": {"email": email, "password": password}})
        return t.AuthToken.from_dict(res or {})
