"""Admin client unit tests (graphql + rest), mocked with respx."""

from __future__ import annotations

import pytest
import respx
from httpx import Response

from authorizer import types as t
from authorizer.admin_client import AuthorizerAdminClient
from authorizer.exceptions import AuthorizerError

URL = "https://auth.example.com"


def _admin(protocol: str = "graphql") -> AuthorizerAdminClient:
    return AuthorizerAdminClient(URL, "admin", protocol=protocol)


def test_requires_admin_secret() -> None:
    with pytest.raises(ValueError):
        AuthorizerAdminClient(URL, "")


@respx.mock
def test_admin_login_sends_secret_header() -> None:
    route = respx.post(f"{URL}/graphql").mock(
        return_value=Response(200, json={"data": {"_admin_login": {"message": "ok"}}})
    )
    with _admin() as c:
        out = c.admin_login(t.AdminLoginRequest(admin_secret="admin"))
    assert out.message == "ok"
    assert route.calls[0].request.headers["x-authorizer-admin-secret"] == "admin"


@respx.mock
def test_users_graphql_parses_pagination_and_users() -> None:
    respx.post(f"{URL}/graphql").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "_users": {
                        "pagination": {"total": 1, "page": 1, "limit": 10, "offset": 0},
                        "users": [{"id": "1", "email": "a@b.com"}],
                    }
                }
            },
        )
    )
    with _admin() as c:
        out = c.users()
    assert out.pagination.total == 1
    assert out.users[0].email == "a@b.com"


@respx.mock
def test_user_graphql() -> None:
    respx.post(f"{URL}/graphql").mock(
        return_value=Response(200, json={"data": {"_user": {"id": "1", "email": "a@b.com"}}})
    )
    with _admin() as c:
        assert c.user(t.GetUserRequest(email="a@b.com")).id == "1"


@respx.mock
def test_update_user_returns_user() -> None:
    respx.post(f"{URL}/graphql").mock(
        return_value=Response(200, json={"data": {"_update_user": {"id": "1", "roles": ["admin"]}}})
    )
    with _admin() as c:
        out = c.update_user(t.UpdateUserRequest(id="1", roles=["admin"]))
    assert out.roles == ["admin"]


@respx.mock
def test_delete_user_destructive_message() -> None:
    respx.post(f"{URL}/graphql").mock(
        return_value=Response(200, json={"data": {"_delete_user": {"message": "deleted"}}})
    )
    with _admin() as c:
        assert c.delete_user(t.DeleteUserRequest(email="a@b.com")).message == "deleted"


@respx.mock
def test_invite_members_handles_capitalized_users_key() -> None:
    respx.post(f"{URL}/graphql").mock(
        return_value=Response(
            200,
            json={"data": {"_invite_members": {"message": "sent", "Users": [{"id": "9"}]}}},
        )
    )
    with _admin() as c:
        out = c.invite_members(t.InviteMembersRequest(emails=["a@b.com"]))
    assert out.message == "sent"
    assert out.users[0].id == "9"


@respx.mock
def test_fga_write_model_returns_model() -> None:
    respx.post(f"{URL}/graphql").mock(
        return_value=Response(
            200, json={"data": {"_fga_write_model": {"id": "m1", "dsl": "model"}}}
        )
    )
    with _admin() as c:
        out = c.fga_write_model(t.FgaWriteModelRequest(dsl="model"))
    assert out.id == "m1"


@respx.mock
def test_fga_read_tuples() -> None:
    respx.post(f"{URL}/graphql").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "_fga_read_tuples": {
                        "tuples": [{"user": "user:1", "relation": "r", "object": "o"}],
                        "continuation_token": "x",
                    }
                }
            },
        )
    )
    with _admin() as c:
        out = c.fga_read_tuples(t.FgaReadTuplesRequest())
    assert out.tuples[0].user == "user:1"
    assert out.continuation_token == "x"


# -- graphql-unsupported methods --------------------------------------------- #
def test_admin_meta_not_available_over_graphql() -> None:
    with _admin("graphql") as c:
        with pytest.raises(AuthorizerError) as ei:
            c.admin_meta()
    assert "not available over graphql" in str(ei.value)


def test_fga_reset_not_available_over_graphql() -> None:
    with _admin("graphql") as c:
        with pytest.raises(AuthorizerError):
            c.fga_reset()


def test_admin_signup_not_available_over_rest() -> None:
    with _admin("rest") as c:
        with pytest.raises(AuthorizerError) as ei:
            c.admin_signup(t.AdminSignupRequest(admin_secret="admin"))
    assert "not available over rest" in str(ei.value)


# -- REST transport ---------------------------------------------------------- #
@respx.mock
def test_admin_meta_rest_get_and_unwrap() -> None:
    route = respx.get(f"{URL}/v1/admin/meta").mock(
        return_value=Response(200, json={"admin_meta": {"roles": ["admin"]}})
    )
    with _admin("rest") as c:
        out = c.admin_meta()
    assert out.roles == ["admin"]
    assert route.calls[0].request.headers["x-authorizer-admin-secret"] == "admin"


@respx.mock
def test_users_rest_post() -> None:
    respx.post(f"{URL}/v1/admin/users").mock(
        return_value=Response(
            200,
            json={"users": [{"id": "1"}], "pagination": {"total": 1}},
        )
    )
    with _admin("rest") as c:
        out = c.users()
    assert out.users[0].id == "1"
    assert out.pagination.total == 1


@respx.mock
def test_fga_reset_rest() -> None:
    respx.post(f"{URL}/v1/admin/fga/reset").mock(
        return_value=Response(200, json={"message": "reset"})
    )
    with _admin("rest") as c:
        assert c.fga_reset().message == "reset"
