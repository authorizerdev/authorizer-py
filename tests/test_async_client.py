"""Async client smoke tests — mirror of the most important sync paths."""

from __future__ import annotations

import json

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
    assert json.loads(route.calls[0].request.content)["client_id"] == "cid"


@pytest.mark.asyncio
async def test_async_init_validation() -> None:
    with pytest.raises(ValueError):
        AsyncAuthorizerClient("", "https://auth.example.com")
