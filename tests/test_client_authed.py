# tests/test_client_authed.py
import json

import pytest
import respx
from httpx import Response

from authorizer import types as t
from authorizer.client import AuthorizerClient
from authorizer.exceptions import AuthorizerError

BEARER = {"Authorization": "Bearer tok"}


def _client():
    return AuthorizerClient("cid", "https://auth.example.com")


@respx.mock
def test_get_profile_passes_auth_header():
    route = respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(200, json={"data": {"profile": {"id": "1", "email": "a@b.com"}}})
    )
    with _client() as c:
        user = c.get_profile(headers=BEARER)
    assert user.email == "a@b.com"
    assert route.calls[0].request.headers["authorization"] == "Bearer tok"


@respx.mock
def test_update_profile():
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(200, json={"data": {"update_profile": {"message": "updated"}}})
    )
    with _client() as c:
        out = c.update_profile(t.UpdateProfileRequest(given_name="Jo"), headers=BEARER)
    assert out.message == "updated"


@respx.mock
def test_get_session():
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(200, json={"data": {"session": {"access_token": "tok"}}})
    )
    with _client() as c:
        out = c.get_session(headers=BEARER)
    assert out.access_token == "tok"


@respx.mock
def test_logout_and_deactivate():
    respx.post("https://auth.example.com/graphql").mock(
        side_effect=[
            Response(200, json={"data": {"logout": {"message": "bye"}}}),
            Response(200, json={"data": {"deactivate_account": {"message": "gone"}}}),
        ]
    )
    with _client() as c:
        assert c.logout(headers=BEARER).message == "bye"
        assert c.deactivate_account(headers=BEARER).message == "gone"


@respx.mock
def test_check_permissions():
    check_result = {"relation": "can_view", "object": "document:1", "allowed": True}
    route = respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(
            200, json={"data": {"check_permissions": {"results": [check_result]}}}
        )
    )
    with _client() as c:
        out = c.check_permissions(
            t.CheckPermissionsRequest(
                checks=[t.PermissionCheckInput(relation="can_view", object="document:1")]
            ),
            headers=BEARER,
        )
    assert out.results[0].allowed is True
    sent = json.loads(route.calls[0].request.content)
    assert sent["variables"]["data"]["checks"] == [
        {"relation": "can_view", "object": "document:1"}
    ]


@respx.mock
def test_list_permissions():
    lp_data = {
        "objects": ["document:1"],
        "permissions": [{"object": "document:1", "relation": "can_view"}],
        "truncated": False,
    }
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(200, json={"data": {"list_permissions": lp_data}})
    )
    with _client() as c:
        out = c.list_permissions(
            t.ListPermissionsRequest(relation="can_view", object_type="document"), headers=BEARER
        )
    assert out.objects == ["document:1"]


@respx.mock
def test_get_token_oauth_endpoint():
    route = respx.post("https://auth.example.com/oauth/token").mock(
        return_value=Response(
            200, json={"access_token": "tok", "expires_in": 3600, "id_token": "id"}
        )
    )
    with _client() as c:
        out = c.get_token(t.GetTokenRequest(code="abc", code_verifier="ver"))
    assert out.access_token == "tok"
    sent = json.loads(route.calls[0].request.content)
    assert sent["client_id"] == "cid"
    assert sent["grant_type"] == "authorization_code"
    assert sent["code"] == "abc"


def test_get_token_refresh_requires_token():
    import pytest

    with _client() as c:
        with pytest.raises(ValueError):
            c.get_token(t.GetTokenRequest(grant_type="refresh_token"))


@respx.mock
def test_revoke_token():
    route = respx.post("https://auth.example.com/oauth/revoke").mock(
        return_value=Response(200, json={"message": "revoked"})
    )
    with _client() as c:
        out = c.revoke_token(t.RevokeTokenRequest(refresh_token="r"))
    assert out.message == "revoked"
    sent = json.loads(route.calls[0].request.content)
    assert sent == {"refresh_token": "r", "client_id": "cid"}


@respx.mock
def test_graphql_query_escape_hatch():
    respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(200, json={"data": {"profile": {"id": "1"}}})
    )
    with _client() as c:
        out = c.graphql_query("query { profile { id } }", headers=BEARER)
    assert out == {"profile": {"id": "1"}}


def test_graphql_query_raises_on_graphql_errors_2xx():
    with respx.mock:
        respx.post("https://auth.example.com/graphql").mock(
            return_value=Response(200, json={"errors": [{"message": "nope"}]})
        )
        with _client() as c:
            with pytest.raises(AuthorizerError, match="nope"):
                c.graphql_query("query { profile { id } }")


def test_typed_method_raises_on_graphql_errors():
    with respx.mock:
        respx.post("https://auth.example.com/graphql").mock(
            return_value=Response(200, json={"errors": [{"message": "Unauthorized"}]})
        )
        with _client() as c:
            with pytest.raises(AuthorizerError, match="Unauthorized"):
                c.get_profile(headers={"Authorization": "Bearer t"})
