"""Admin sync/async parity + spec coverage of all 66 admin methods."""

from __future__ import annotations

from authorizer import _dispatch as d
from authorizer.admin_client import AuthorizerAdminClient
from authorizer.async_admin_client import AsyncAuthorizerAdminClient

# 32 proto RPCs + 3 gql-only extras.
ADMIN_METHODS = [
    "admin_login",
    "admin_logout",
    "admin_session",
    "admin_meta",
    "users",
    "user",
    "update_user",
    "delete_user",
    "verification_requests",
    "revoke_access",
    "enable_access",
    "invite_members",
    "add_webhook",
    "update_webhook",
    "delete_webhook",
    "get_webhook",
    "webhooks",
    "webhook_logs",
    "test_endpoint",
    "add_email_template",
    "update_email_template",
    "delete_email_template",
    "email_templates",
    "audit_logs",
    "fga_get_model",
    "fga_write_model",
    "fga_write_tuples",
    "fga_delete_tuples",
    "fga_read_tuples",
    "fga_list_users",
    "fga_expand",
    "fga_reset",
    "admin_signup",
    "update_env",
    "generate_jwt_keys",
    # Machine-agent-identity ops (graphql-only until the vendored stubs are
    # re-vendored; orgs/SSO/SCIM are graphql-only on the server too).
    "create_client",
    "update_client",
    "delete_client",
    "rotate_client_secret",
    "get_client",
    "clients",
    "add_trusted_issuer",
    "update_trusted_issuer",
    "delete_trusted_issuer",
    "get_trusted_issuer",
    "trusted_issuers",
    "create_organization",
    "update_organization",
    "delete_organization",
    "add_org_member",
    "remove_org_member",
    "get_organization",
    "organizations",
    "org_members",
    "create_org_oidc_connection",
    "update_org_oidc_connection",
    "delete_org_oidc_connection",
    "get_org_oidc_connection",
    "create_org_saml_connection",
    "update_org_saml_connection",
    "delete_org_saml_connection",
    "get_org_saml_connection",
    "create_scim_endpoint",
    "rotate_scim_token",
    "delete_scim_endpoint",
    "get_scim_endpoint",
]


def test_both_admin_clients_expose_same_surface() -> None:
    for name in ADMIN_METHODS:
        assert hasattr(AuthorizerAdminClient, name), f"sync admin missing {name}"
        assert hasattr(AsyncAuthorizerAdminClient, name), f"async admin missing {name}"


def test_dispatch_table_covers_every_admin_method() -> None:
    assert set(d.ADMIN) == set(ADMIN_METHODS)
    assert len(d.ADMIN) == 66


def test_protocol_availability_matches_spec() -> None:
    # gql-only extras
    for name in ("admin_signup", "update_env", "generate_jwt_keys"):
        assert d.ADMIN[name].protocols == ("graphql",)
    # rest+grpc only (no graphql op)
    for name in ("admin_logout", "admin_session", "admin_meta", "fga_get_model", "fga_reset"):
        assert d.ADMIN[name].protocols == ("rest", "grpc")
    # full coverage
    assert d.ADMIN["users"].protocols == ("graphql", "rest", "grpc")
    # machine-agent-identity ops are graphql-only for now
    for name in ("create_client", "trusted_issuers", "create_organization", "get_scim_endpoint"):
        assert d.ADMIN[name].protocols == ("graphql",)
