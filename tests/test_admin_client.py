"""Admin client unit tests (graphql + rest), mocked with respx."""

from __future__ import annotations

import json

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


# -- machine-agent-identity ops (graphql-only) -------------------------------- #
@respx.mock
def test_create_client_returns_secret_once() -> None:
    route = respx.post(f"{URL}/graphql").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "_create_client": {
                        "client": {
                            "id": "c1",
                            "name": "agent",
                            "allowed_scopes": ["read:users"],
                            "is_active": True,
                        },
                        "client_secret": "shown-once",
                    }
                }
            },
        )
    )
    with _admin() as c:
        out = c.create_client(
            t.CreateClientRequest(name="agent", allowed_scopes=["read:users"])
        )
    assert out.client.id == "c1"
    assert out.client.allowed_scopes == ["read:users"]
    assert out.client_secret == "shown-once"
    body = json.loads(route.calls[0].request.content)
    assert "_create_client" in body["query"]
    assert body["variables"]["data"] == {"name": "agent", "allowed_scopes": ["read:users"]}


@respx.mock
def test_clients_parses_pagination_and_list() -> None:
    respx.post(f"{URL}/graphql").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "_clients": {
                        "pagination": {"total": 2, "page": 1, "limit": 10, "offset": 0},
                        "clients": [{"id": "c1", "name": "a"}, {"id": "c2", "name": "b"}],
                    }
                }
            },
        )
    )
    with _admin() as c:
        out = c.clients()
    assert out.pagination.total == 2
    assert [x.id for x in out.clients] == ["c1", "c2"]


@respx.mock
def test_add_trusted_issuer() -> None:
    route = respx.post(f"{URL}/graphql").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "_add_trusted_issuer": {
                        "id": "ti1",
                        "service_account_id": "c1",
                        "name": "k8s",
                        "issuer_url": "https://k8s.local",
                        "key_source_type": "oidc_discovery",
                        "expected_aud": "authorizer",
                        "subject_claim": "sub",
                        "issuer_type": "kubernetes_sa",
                        "is_active": True,
                    }
                }
            },
        )
    )
    with _admin() as c:
        out = c.add_trusted_issuer(
            t.AddTrustedIssuerRequest(
                service_account_id="c1",
                name="k8s",
                issuer_url="https://k8s.local",
                key_source_type="oidc_discovery",
                expected_aud="authorizer",
                issuer_type="kubernetes_sa",
                allowed_subjects="system:serviceaccount:ns:sa",
            )
        )
    assert out.id == "ti1"
    assert out.issuer_type == "kubernetes_sa"
    sent = json.loads(route.calls[0].request.content)["variables"]["data"]
    assert sent["allowed_subjects"] == "system:serviceaccount:ns:sa"
    assert "jwks_url" not in sent  # unset optionals are dropped


@respx.mock
def test_create_organization_and_add_member() -> None:
    respx.post(f"{URL}/graphql").mock(
        side_effect=[
            Response(
                200,
                json={"data": {"_create_organization": {"id": "o1", "name": "acme"}}},
            ),
            Response(
                200,
                json={
                    "data": {
                        "_add_org_member": {
                            "id": "m1",
                            "org_id": "o1",
                            "user_id": "u1",
                            "roles": ["admin"],
                        }
                    }
                },
            ),
        ]
    )
    with _admin() as c:
        org = c.create_organization(t.CreateOrganizationRequest(name="acme"))
        member = c.add_org_member(
            t.AddOrgMemberRequest(org_id=org.id, user_id="u1", roles=["admin"])
        )
    assert org.name == "acme"
    assert member.roles == ["admin"]


@respx.mock
def test_rotate_scim_token_returns_token_once() -> None:
    respx.post(f"{URL}/graphql").mock(
        return_value=Response(
            200,
            json={
                "data": {
                    "_rotate_scim_token": {
                        "scim_endpoint": {"id": "s1", "org_id": "o1", "enabled": True},
                        "token": "bearer-once",
                    }
                }
            },
        )
    )
    with _admin() as c:
        out = c.rotate_scim_token(t.ScimEndpointRequest(org_id="o1"))
    assert out.scim_endpoint.id == "s1"
    assert out.token == "bearer-once"


def test_org_methods_not_available_over_rest() -> None:
    # Organizations/SSO/SCIM/user_organizations/org_domains have no proto RPC
    # on the server (unlike clients/trusted issuers/SAML IdP, which do) --
    # graphql-only for now.
    with _admin("rest") as c:
        with pytest.raises(AuthorizerError) as ei:
            c.create_organization(t.CreateOrganizationRequest(name="acme"))
    assert "not available over rest" in str(ei.value)
    with _admin("rest") as c:
        with pytest.raises(AuthorizerError):
            c.organizations()


@pytest.mark.asyncio
@respx.mock
async def test_async_create_client_and_org_oidc_connection() -> None:
    from authorizer.async_admin_client import AsyncAuthorizerAdminClient

    respx.post(f"{URL}/graphql").mock(
        side_effect=[
            Response(
                200,
                json={
                    "data": {
                        "_create_client": {
                            "client": {"id": "c1", "name": "agent"},
                            "client_secret": "sec",
                        }
                    }
                },
            ),
            Response(
                200,
                json={
                    "data": {
                        "_create_org_oidc_connection": {
                            "id": "oc1",
                            "org_id": "o1",
                            "name": "okta",
                            "issuer_url": "https://okta.example.com",
                            "sso_client_id": "up-cid",
                            "is_active": True,
                        }
                    }
                },
            ),
        ]
    )
    async with AsyncAuthorizerAdminClient(URL, "admin") as c:
        created = await c.create_client(
            t.CreateClientRequest(name="agent", allowed_scopes=["read:users"])
        )
        conn = await c.create_org_oidc_connection(
            t.CreateOrgOIDCConnectionRequest(
                org_id="o1",
                name="okta",
                issuer_url="https://okta.example.com",
                client_id="up-cid",
                client_secret="up-sec",
            )
        )
    assert created.client_secret == "sec"
    assert conn.sso_client_id == "up-cid"
