# tests/test_client_public.py
import respx
from httpx import Response

from authorizer import types as t
from authorizer.client import AuthorizerClient

AUTH = {"data": {"login": {"access_token": "tok"}}}


def _client():
    return AuthorizerClient("cid", "https://auth.example.com")


@respx.mock
def test_login():
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(200, json={"data": {"login": {"access_token": "tok"}}})
    )
    with _client() as c:
        assert c.login(t.LoginRequest(password="p", email="a@b.com")).access_token == "tok"


@respx.mock
def test_signup():
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(200, json={"data": {"signup": {"access_token": "tok"}}})
    )
    with _client() as c:
        out = c.signup(t.SignUpRequest(password="p", confirm_password="p", email="a@b.com"))
    assert out.access_token == "tok"


@respx.mock
def test_magic_link_login():
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(200, json={"data": {"magic_link_login": {"message": "sent"}}})
    )
    with _client() as c:
        assert c.magic_link_login(t.MagicLinkLoginRequest(email="a@b.com")).message == "sent"


@respx.mock
def test_forgot_password():
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "forgot_password": {"message": "ok", "should_show_mobile_otp_screen": False}
                }
            },
        )
    )
    with _client() as c:
        out = c.forgot_password(t.ForgotPasswordRequest(email="a@b.com"))
    assert out.message == "ok"


@respx.mock
def test_validate_jwt_token():
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "validate_jwt_token": {"is_valid": True, "claims": {"sub": "1"}}
                }
            },
        )
    )
    with _client() as c:
        out = c.validate_jwt_token(
            t.ValidateJWTTokenRequest(token="x", token_type=t.TokenType.ACCESS_TOKEN)
        )
    assert out.is_valid is True
    assert out.claims == {"sub": "1"}


@respx.mock
def test_validate_session():
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(
            200,
            json={"data": {"validate_session": {"is_valid": True, "user": {"id": "1"}}}},
        )
    )
    with _client() as c:
        out = c.validate_session(t.ValidateSessionRequest())
    assert out.is_valid is True
    assert out.user.id == "1"


@respx.mock
def test_get_meta_data():
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "meta": {"version": "1.0", "client_id": "cid", "is_sign_up_enabled": True}
                }
            },
        )
    )
    with _client() as c:
        out = c.get_meta_data()
    assert out.version == "1.0"
    assert out.is_sign_up_enabled is True
