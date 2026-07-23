"""Admin sync/async parity + spec coverage of all admin methods."""

from __future__ import annotations

from authorizer import _dispatch as d
from authorizer.admin_client import AuthorizerAdminClient
from authorizer.async_admin_client import AsyncAuthorizerAdminClient

# Proto RPCs (clients/trusted issuers/SAML IdP now full graphql+rest+grpc,
# re-vendored from server HEAD ca628cee) + graphql-only extras (orgs/SSO/SCIM/
# user_organizations/org_domains have no proto RPC on the server).
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
    # Machine-agent-identity ops: clients + trusted issuers have proto RPCs
    # (full graphql+rest+grpc); orgs/SSO/SCIM are graphql-only on the server.
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
    # SAML IdP (Authorizer as Identity Provider for downstream SPs) — proto RPCs.
    "create_saml_service_provider",
    "update_saml_service_provider",
    "delete_saml_service_provider",
    "get_saml_service_provider",
    "list_saml_service_providers",
    "rotate_saml_idp_cert",
    "retire_saml_idp_key",
    "list_saml_idp_keys",
    "import_saml_sp_metadata",
    # graphql-only: no proto RPC on the server.
    "user_organizations",
    "request_org_domain",
    "verify_org_domain",
    "add_verified_org_domain",
    "delete_org_domain",
    "org_domains",
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
    assert len(d.ADMIN) == len(ADMIN_METHODS)


def test_protocol_availability_matches_spec() -> None:
    # gql-only extras
    for name in ("admin_signup", "update_env", "generate_jwt_keys"):
        assert d.ADMIN[name].protocols == ("graphql",)
    # rest+grpc only (no graphql op)
    for name in ("admin_logout", "admin_session", "admin_meta", "fga_get_model", "fga_reset"):
        assert d.ADMIN[name].protocols == ("rest", "grpc")
    # full coverage
    assert d.ADMIN["users"].protocols == ("graphql", "rest", "grpc")
    # machine-agent-identity ops (clients/trusted issuers/SAML IdP) have proto
    # RPCs -- full coverage now that the stubs are re-vendored.
    for name in ("create_client", "trusted_issuers", "create_saml_service_provider"):
        assert d.ADMIN[name].protocols == ("graphql", "rest", "grpc")
    # orgs/SSO/SCIM/user_organizations/org_domains are graphql-only on the server.
    for name in ("create_organization", "get_scim_endpoint", "user_organizations", "org_domains"):
        assert d.ADMIN[name].protocols == ("graphql",)
