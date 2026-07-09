"""Async client smoke tests — mirror of the most important sync paths."""

from __future__ import annotations

from urllib.parse import parse_qs

import pytest
import respx
from httpx import Response

from authorizer import types as t
from authorizer.async_client import AsyncAuthorizerClient


@pytest.mark.asyncio
@respx.mock
async def test_async_login() -> None:
    route = respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(200, json={"data": {"login": {"access_token": "tok"}}})
    )
    async with AsyncAuthorizerClient("cid", "https://auth.example.com") as c:
        out = await c.login(t.LoginRequest(password="p", email="a@b.com"))
    assert out.access_token == "tok"
    assert route.calls[0].request.headers["x-authorizer-client-id"] == "cid"


@pytest.mark.asyncio
@respx.mock
async def test_async_check_permissions() -> None:
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "check_permissions": {
                        "results": [{"relation": "r", "object": "o", "allowed": True}]
                    }
                }
            },
        )
    )
    async with AsyncAuthorizerClient("cid", "https://auth.example.com") as c:
        out = await c.check_permissions(
            t.CheckPermissionsRequest(
                checks=[t.PermissionCheckInput(relation="r", object="o")]
            ),
            headers={"Authorization": "Bearer t"},
        )
    assert out.results[0].allowed is True


@pytest.mark.asyncio
@respx.mock
async def test_async_get_token() -> None:
    route = respx.post("https://auth.example.com/oauth/token").mock(
        return_value=Response(
            200, json={"access_token": "tok", "expires_in": 1, "id_token": "id"}
        )
    )
    async with AsyncAuthorizerClient("cid", "https://auth.example.com") as c:
        out = await c.get_token(t.GetTokenRequest(code="abc", code_verifier="ver"))
    assert out.access_token == "tok"
    request = route.calls[0].request
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    sent = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
    assert sent["client_id"] == "cid"


@pytest.mark.asyncio
@respx.mock
async def test_async_get_token_token_exchange_form_body() -> None:
    route = respx.post("https://auth.example.com/oauth/token").mock(
        return_value=Response(
            200,
            json={
                "access_token": "delegated",
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "read:docs",
            },
        )
    )
    async with AsyncAuthorizerClient("cid", "https://auth.example.com") as c:
        out = await c.get_token(
            t.GetTokenRequest(
                grant_type=t.GRANT_TYPE_TOKEN_EXCHANGE,
                client_secret="agent-secret",
                subject_token="user-tok",
                subject_token_type=t.TOKEN_TYPE_ACCESS_TOKEN,
                actor_token="agent-tok",
                actor_token_type=t.TOKEN_TYPE_ACCESS_TOKEN,
                resource="https://api.example.com",
            )
        )
    assert out.access_token == "delegated"
    assert out.token_type == "Bearer"
    sent = {k: v[0] for k, v in parse_qs(route.calls[0].request.content.decode()).items()}
    assert sent == {
        "client_id": "cid",
        "grant_type": t.GRANT_TYPE_TOKEN_EXCHANGE,
        "client_secret": "agent-secret",
        "subject_token": "user-tok",
        "subject_token_type": t.TOKEN_TYPE_ACCESS_TOKEN,
        "actor_token": "agent-tok",
        "actor_token_type": t.TOKEN_TYPE_ACCESS_TOKEN,
        "resource": "https://api.example.com",
    }


@pytest.mark.asyncio
async def test_async_init_validation() -> None:
    with pytest.raises(ValueError):
        AsyncAuthorizerClient("", "https://auth.example.com")
