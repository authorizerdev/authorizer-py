"""Protocol selection (graphql/rest/grpc) on the public clients."""

from __future__ import annotations

import json

import pytest
import respx
from httpx import Response

from authorizer import types as t
from authorizer.async_client import AsyncAuthorizerClient
from authorizer.client import AuthorizerClient
from authorizer.exceptions import AuthorizerError

URL_GRPC = "http://localhost:8080"


def test_invalid_protocol_rejected() -> None:
    with pytest.raises(ValueError):
        AuthorizerClient("cid", "https://auth.example.com", protocol="soap")


@respx.mock
def test_rest_signup_flat_auth_response() -> None:
    # rc.9: ALL public RPCs work over rest; the response envelope is FLAT
    # (Signup -> AuthResponse), so access_token sits at the top level.
    route = respx.post("https://auth.example.com/v1/signup").mock(
        return_value=Response(200, json={"access_token": "tok"})
    )
    with AuthorizerClient("cid", "https://auth.example.com", protocol="rest") as c:
        out = c.signup(t.SignUpRequest(password="p", email="a@b.com", confirm_password="p"))
    assert out.access_token == "tok"
    sent = json.loads(route.calls[0].request.content)
    assert sent["email"] == "a@b.com"  # flat REST body, no graphql wrapping


@respx.mock
def test_rest_login_now_supported() -> None:
    # rc.9: login (and the other formerly graphql-only methods) work over rest.
    respx.post("https://auth.example.com/v1/login").mock(
        return_value=Response(200, json={"access_token": "tok"})
    )
    with AuthorizerClient("cid", "https://auth.example.com", protocol="rest") as c:
        out = c.login(t.LoginRequest(password="p", email="a@b.com"))
    assert out.access_token == "tok"


@respx.mock
def test_rest_meta_is_get_and_flat() -> None:
    # rc.9: Meta -> Meta (flat), version at the top level.
    respx.get("https://auth.example.com/v1/meta").mock(
        return_value=Response(200, json={"version": "2.3.0"})
    )
    with AuthorizerClient("cid", "https://auth.example.com", protocol="rest") as c:
        assert c.get_meta_data().version == "2.3.0"


@respx.mock
def test_rest_message_response_not_unwrapped() -> None:
    # logout is available over rest and returns a flat {message} (no wrapper).
    respx.post("https://auth.example.com/v1/logout").mock(
        return_value=Response(200, json={"message": "logged out"})
    )
    with AuthorizerClient("cid", "https://auth.example.com", protocol="rest") as c:
        assert c.logout().message == "logged out"


@respx.mock
def test_rest_error_surfaces_message() -> None:
    respx.post("https://auth.example.com/v1/signup").mock(
        return_value=Response(400, json={"message": "bad creds"})
    )
    with AuthorizerClient("cid", "https://auth.example.com", protocol="rest") as c:
        with pytest.raises(AuthorizerError) as ei:
            c.signup(t.SignUpRequest(password="p", email="a@b.com", confirm_password="p"))
    assert "bad creds" in str(ei.value)


@pytest.mark.asyncio
@respx.mock
async def test_async_rest_signup() -> None:
    respx.post("https://auth.example.com/v1/signup").mock(
        return_value=Response(200, json={"access_token": "tok"})
    )
    async with AsyncAuthorizerClient("cid", "https://auth.example.com", protocol="rest") as c:
        out = await c.signup(t.SignUpRequest(password="p", email="a@b.com", confirm_password="p"))
    assert out.access_token == "tok"


def test_grpc_dispatch_routes_to_transport(monkeypatch: pytest.MonkeyPatch) -> None:
    import authorizer._grpc_transport as g

    captured: dict[str, object] = {}

    class FakeChannel:
        def close(self) -> None:
            captured["closed"] = True

    channel = FakeChannel()
    monkeypatch.setattr(g, "make_channel", lambda url, endpoint="": channel)

    def fake_call(ch, spec, data, metadata, admin):  # type: ignore[no-untyped-def]
        captured.update(channel=ch, method=spec.grpc_method, data=data, admin=admin)
        return {"access_token": "tok"}

    monkeypatch.setattr(g, "grpc_call", fake_call)
    with AuthorizerClient("cid", URL_GRPC, protocol="grpc") as c:
        out = c.signup(t.SignUpRequest(password="p", email="a@b.com", confirm_password="p"))
    assert out.access_token == "tok"
    assert captured["channel"] is channel
    assert captured["closed"] is True
    assert captured["method"] == "Signup"
    assert captured["admin"] is False
    assert captured["data"]["email"] == "a@b.com"  # type: ignore[index]


def test_grpc_missing_dependency_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "grpc":
            raise ImportError("no grpc")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with AuthorizerClient("cid", "https://auth.example.com", protocol="grpc") as c:
        with pytest.raises(AuthorizerError) as ei:
            c.signup(t.SignUpRequest(password="p", email="a@b.com", confirm_password="p"))
    assert "authorizer-py[grpc]" in str(ei.value)
