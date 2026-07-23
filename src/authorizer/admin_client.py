"""Synchronous Authorizer admin client.

Admin auth uses the ``x-authorizer-admin-secret`` header (HTTP) / metadata key
(gRPC). The default mechanism is the secret; the admin session cookie flow
(:meth:`admin_login` -> Set-Cookie) is also supported.
"""

from __future__ import annotations

from types import TracebackType
from typing import Any

import httpx

from . import _dispatch as d
from . import types as t
from ._core import (
    PROTOCOLS,
    ClientConfig,
    RequestSpec,
    parse_graphql_response,
    parse_rest,
    prepare_http,
    unsupported_protocol_error,
)
from ._dispatch import MethodSpec
from .exceptions import AuthorizerConnectionError


class AuthorizerAdminClient:
    """Synchronous client for Authorizer's super-admin-only API surface."""

    _ADMIN = True

    def __init__(
        self,
        authorizer_url: str,
        admin_secret: str,
        extra_headers: dict[str, str] | None = None,
        protocol: str = "graphql",
        grpc_endpoint: str = "",
    ) -> None:
        if not authorizer_url or not authorizer_url.strip():
            raise ValueError("authorizer_url is required")
        if not admin_secret or not admin_secret.strip():
            raise ValueError("admin_secret is required")
        if protocol not in PROTOCOLS:
            raise ValueError(f"protocol must be one of {PROTOCOLS}, got {protocol!r}")
        self._config = ClientConfig(
            client_id="",
            authorizer_url=authorizer_url.strip().rstrip("/"),
            redirect_url="",
            extra_headers=dict(extra_headers or {}),
            protocol=protocol,
            admin_secret=admin_secret,
            grpc_endpoint=grpc_endpoint.strip(),
        )
        self._http = httpx.Client()
        self._channel: Any = None

    # -- lifecycle -------------------------------------------------------- #
    def close(self) -> None:
        self._http.close()
        if self._channel is not None:
            self._channel.close()
            self._channel = None

    def __enter__(self) -> AuthorizerAdminClient:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- dispatch --------------------------------------------------------- #
    def _send(self, spec: RequestSpec) -> httpx.Response:
        try:
            return self._http.request(spec.method, spec.url, json=spec.json, headers=spec.headers)
        except httpx.HTTPError as e:
            raise AuthorizerConnectionError(str(e)) from e

    def _invoke(
        self,
        method: str,
        spec: MethodSpec,
        data: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> dict[str, Any] | None:
        proto = self._config.protocol
        if proto not in spec.protocols:
            raise unsupported_protocol_error(method, proto, spec.protocols)
        if proto == "grpc":
            from . import _grpc_transport as g

            if self._channel is None:
                self._channel = g.make_channel(
                    self._config.authorizer_url, self._config.grpc_endpoint
                )
            md = g.grpc_metadata(self._config, headers)
            return g.grpc_call(self._channel, spec, data, md, self._ADMIN)
        req, kind, unwrap = prepare_http(self._config, spec, data, headers)
        res = self._send(req)
        if kind == "rest":
            return parse_rest(spec, res.status_code, res.content, unwrap, self._ADMIN)
        return parse_graphql_response(res.status_code, res.content, unwrap or "")

    # -- admin auth + meta ------------------------------------------------ #
    def admin_login(self, req: t.AdminLoginRequest) -> t.GenericResponse:
        res = self._invoke("admin_login", d.ADMIN["admin_login"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def admin_logout(self) -> t.GenericResponse:
        res = self._invoke("admin_logout", d.ADMIN["admin_logout"], None)
        return t.GenericResponse.from_dict(res or {})

    def admin_session(self) -> t.GenericResponse:
        res = self._invoke("admin_session", d.ADMIN["admin_session"], None)
        return t.GenericResponse.from_dict(res or {})

    def admin_meta(self) -> t.AdminMeta:
        res = self._invoke("admin_meta", d.ADMIN["admin_meta"], None)
        return t.AdminMeta.from_dict(res or {})

    def admin_signup(self, req: t.AdminSignupRequest) -> t.GenericResponse:
        res = self._invoke("admin_signup", d.ADMIN["admin_signup"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def update_env(self, env: dict[str, Any]) -> t.GenericResponse:
        res = self._invoke("update_env", d.ADMIN["update_env"], env)
        return t.GenericResponse.from_dict(res or {})

    def generate_jwt_keys(self, req: t.GenerateJWTKeysRequest) -> t.GenerateJWTKeysResponse:
        res = self._invoke("generate_jwt_keys", d.ADMIN["generate_jwt_keys"], req.to_dict())
        return t.GenerateJWTKeysResponse.from_dict(res or {})

    # -- users ------------------------------------------------------------ #
    def users(self, req: t.ListUsersRequest | None = None) -> t.UsersResponse:
        res = self._invoke("users", d.ADMIN["users"], req.to_dict() if req else None)
        return t.UsersResponse.from_dict(res or {})

    def user(self, req: t.GetUserRequest) -> t.User:
        res = self._invoke("user", d.ADMIN["user"], req.to_dict())
        return t.User.from_dict(res or {})

    def update_user(self, req: t.UpdateUserRequest) -> t.User:
        res = self._invoke("update_user", d.ADMIN["update_user"], req.to_dict())
        return t.User.from_dict(res or {})

    def delete_user(self, req: t.DeleteUserRequest) -> t.GenericResponse:
        """Destructive: permanently deletes the user and associated OTP/verification data."""
        res = self._invoke("delete_user", d.ADMIN["delete_user"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def verification_requests(
        self, req: t.PaginationRequest | None = None
    ) -> t.VerificationRequestsResponse:
        res = self._invoke(
            "verification_requests", d.ADMIN["verification_requests"],
            req.to_dict() if req else None,
        )
        return t.VerificationRequestsResponse.from_dict(res or {})

    # -- access ----------------------------------------------------------- #
    def revoke_access(self, req: t.UpdateAccessRequest) -> t.GenericResponse:
        res = self._invoke("revoke_access", d.ADMIN["revoke_access"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def enable_access(self, req: t.UpdateAccessRequest) -> t.GenericResponse:
        res = self._invoke("enable_access", d.ADMIN["enable_access"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def invite_members(self, req: t.InviteMembersRequest) -> t.InviteMembersResponse:
        res = self._invoke("invite_members", d.ADMIN["invite_members"], req.to_dict())
        return t.InviteMembersResponse.from_dict(res or {})

    # -- webhooks --------------------------------------------------------- #
    def add_webhook(self, req: t.AddWebhookRequest) -> t.GenericResponse:
        res = self._invoke("add_webhook", d.ADMIN["add_webhook"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def update_webhook(self, req: t.UpdateWebhookRequest) -> t.GenericResponse:
        res = self._invoke("update_webhook", d.ADMIN["update_webhook"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def delete_webhook(self, req: t.WebhookRequest) -> t.GenericResponse:
        """Destructive: permanently deletes the webhook."""
        res = self._invoke("delete_webhook", d.ADMIN["delete_webhook"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def get_webhook(self, req: t.WebhookRequest) -> t.Webhook:
        res = self._invoke("get_webhook", d.ADMIN["get_webhook"], req.to_dict())
        return t.Webhook.from_dict(res or {})

    def webhooks(self, req: t.PaginationRequest | None = None) -> t.WebhooksResponse:
        res = self._invoke("webhooks", d.ADMIN["webhooks"], req.to_dict() if req else None)
        return t.WebhooksResponse.from_dict(res or {})

    def webhook_logs(self, req: t.ListWebhookLogRequest | None = None) -> t.WebhookLogsResponse:
        res = self._invoke("webhook_logs", d.ADMIN["webhook_logs"], req.to_dict() if req else None)
        return t.WebhookLogsResponse.from_dict(res or {})

    def test_endpoint(self, req: t.TestEndpointRequest) -> t.TestEndpointResponse:
        res = self._invoke("test_endpoint", d.ADMIN["test_endpoint"], req.to_dict())
        return t.TestEndpointResponse.from_dict(res or {})

    # -- email templates -------------------------------------------------- #
    def add_email_template(self, req: t.AddEmailTemplateRequest) -> t.GenericResponse:
        res = self._invoke("add_email_template", d.ADMIN["add_email_template"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def update_email_template(self, req: t.UpdateEmailTemplateRequest) -> t.GenericResponse:
        res = self._invoke("update_email_template", d.ADMIN["update_email_template"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def delete_email_template(self, req: t.DeleteEmailTemplateRequest) -> t.GenericResponse:
        """Destructive: permanently deletes the email template."""
        res = self._invoke("delete_email_template", d.ADMIN["delete_email_template"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def email_templates(self, req: t.PaginationRequest | None = None) -> t.EmailTemplatesResponse:
        res = self._invoke(
            "email_templates", d.ADMIN["email_templates"], req.to_dict() if req else None
        )
        return t.EmailTemplatesResponse.from_dict(res or {})

    # -- audit ------------------------------------------------------------ #
    def audit_logs(self, req: t.ListAuditLogRequest | None = None) -> t.AuditLogsResponse:
        res = self._invoke("audit_logs", d.ADMIN["audit_logs"], req.to_dict() if req else None)
        return t.AuditLogsResponse.from_dict(res or {})

    # -- FGA -------------------------------------------------------------- #
    def fga_get_model(self) -> t.FgaModel:
        res = self._invoke("fga_get_model", d.ADMIN["fga_get_model"], None)
        return t.FgaModel.from_dict(res or {})

    def fga_write_model(self, req: t.FgaWriteModelRequest) -> t.FgaModel:
        """Destructive: replaces the active fine-grained authorization model."""
        res = self._invoke("fga_write_model", d.ADMIN["fga_write_model"], req.to_dict())
        return t.FgaModel.from_dict(res or {})

    def fga_write_tuples(self, req: t.FgaWriteTuplesRequest) -> t.GenericResponse:
        res = self._invoke("fga_write_tuples", d.ADMIN["fga_write_tuples"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def fga_delete_tuples(self, req: t.FgaWriteTuplesRequest) -> t.GenericResponse:
        """Destructive: removes the given relationship tuples."""
        res = self._invoke("fga_delete_tuples", d.ADMIN["fga_delete_tuples"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def fga_read_tuples(self, req: t.FgaReadTuplesRequest) -> t.FgaReadTuplesResponse:
        res = self._invoke("fga_read_tuples", d.ADMIN["fga_read_tuples"], req.to_dict())
        return t.FgaReadTuplesResponse.from_dict(res or {})

    def fga_list_users(self, req: t.FgaListUsersRequest) -> t.FgaListUsersResponse:
        res = self._invoke("fga_list_users", d.ADMIN["fga_list_users"], req.to_dict())
        return t.FgaListUsersResponse.from_dict(res or {})

    def fga_expand(self, req: t.FgaExpandRequest) -> t.FgaExpandResponse:
        res = self._invoke("fga_expand", d.ADMIN["fga_expand"], req.to_dict())
        return t.FgaExpandResponse.from_dict(res or {})

    def fga_reset(self) -> t.GenericResponse:
        """Destructive: deletes the entire fine-grained authorization store."""
        res = self._invoke("fga_reset", d.ADMIN["fga_reset"], None)
        return t.GenericResponse.from_dict(res or {})

    # -- clients (service accounts / machine identities) ------------------- #
    def create_client(self, req: t.CreateClientRequest) -> t.CreateClientResponse:
        """The returned client_secret is shown ONCE and can never be retrieved again."""
        res = self._invoke("create_client", d.ADMIN["create_client"], req.to_dict())
        return t.CreateClientResponse.from_dict(res or {})

    def update_client(self, req: t.UpdateClientRequest) -> t.Client:
        res = self._invoke("update_client", d.ADMIN["update_client"], req.to_dict())
        return t.Client.from_dict(res or {})

    def delete_client(self, req: t.ClientRequest) -> t.GenericResponse:
        """Destructive: permanently deletes the client; its tokens stop resolving."""
        res = self._invoke("delete_client", d.ADMIN["delete_client"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def rotate_client_secret(self, req: t.ClientRequest) -> t.CreateClientResponse:
        """Destructive: invalidates the old secret; the new one is shown ONCE."""
        res = self._invoke("rotate_client_secret", d.ADMIN["rotate_client_secret"], req.to_dict())
        return t.CreateClientResponse.from_dict(res or {})

    def get_client(self, req: t.ClientRequest) -> t.Client:
        res = self._invoke("get_client", d.ADMIN["get_client"], req.to_dict())
        return t.Client.from_dict(res or {})

    def clients(self, req: t.ListClientsRequest | None = None) -> t.ClientsResponse:
        res = self._invoke("clients", d.ADMIN["clients"], req.to_dict() if req else None)
        return t.ClientsResponse.from_dict(res or {})

    # -- trusted issuers ---------------------------------------------------- #
    def add_trusted_issuer(self, req: t.AddTrustedIssuerRequest) -> t.TrustedIssuer:
        res = self._invoke("add_trusted_issuer", d.ADMIN["add_trusted_issuer"], req.to_dict())
        return t.TrustedIssuer.from_dict(res or {})

    def update_trusted_issuer(self, req: t.UpdateTrustedIssuerRequest) -> t.TrustedIssuer:
        res = self._invoke(
            "update_trusted_issuer", d.ADMIN["update_trusted_issuer"], req.to_dict()
        )
        return t.TrustedIssuer.from_dict(res or {})

    def delete_trusted_issuer(self, req: t.TrustedIssuerRequest) -> t.GenericResponse:
        """Destructive: tokens from this issuer stop authenticating."""
        res = self._invoke(
            "delete_trusted_issuer", d.ADMIN["delete_trusted_issuer"], req.to_dict()
        )
        return t.GenericResponse.from_dict(res or {})

    def get_trusted_issuer(self, req: t.TrustedIssuerRequest) -> t.TrustedIssuer:
        res = self._invoke("get_trusted_issuer", d.ADMIN["get_trusted_issuer"], req.to_dict())
        return t.TrustedIssuer.from_dict(res or {})

    def trusted_issuers(
        self, req: t.ListTrustedIssuersRequest | None = None
    ) -> t.TrustedIssuersResponse:
        res = self._invoke(
            "trusted_issuers", d.ADMIN["trusted_issuers"], req.to_dict() if req else None
        )
        return t.TrustedIssuersResponse.from_dict(res or {})

    # -- organizations ------------------------------------------------------ #
    def create_organization(self, req: t.CreateOrganizationRequest) -> t.Organization:
        res = self._invoke("create_organization", d.ADMIN["create_organization"], req.to_dict())
        return t.Organization.from_dict(res or {})

    def update_organization(self, req: t.UpdateOrganizationRequest) -> t.Organization:
        res = self._invoke("update_organization", d.ADMIN["update_organization"], req.to_dict())
        return t.Organization.from_dict(res or {})

    def delete_organization(self, req: t.OrganizationRequest) -> t.GenericResponse:
        """Destructive: permanently deletes the organization."""
        res = self._invoke("delete_organization", d.ADMIN["delete_organization"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def add_org_member(self, req: t.AddOrgMemberRequest) -> t.OrgMember:
        res = self._invoke("add_org_member", d.ADMIN["add_org_member"], req.to_dict())
        return t.OrgMember.from_dict(res or {})

    def remove_org_member(self, req: t.RemoveOrgMemberRequest) -> t.GenericResponse:
        res = self._invoke("remove_org_member", d.ADMIN["remove_org_member"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def get_organization(self, req: t.OrganizationRequest) -> t.Organization:
        res = self._invoke("get_organization", d.ADMIN["get_organization"], req.to_dict())
        return t.Organization.from_dict(res or {})

    def organizations(
        self, req: t.ListOrganizationsRequest | None = None
    ) -> t.OrganizationsResponse:
        res = self._invoke(
            "organizations", d.ADMIN["organizations"], req.to_dict() if req else None
        )
        return t.OrganizationsResponse.from_dict(res or {})

    def org_members(self, req: t.ListOrgMembersRequest) -> t.OrgMembersResponse:
        res = self._invoke("org_members", d.ADMIN["org_members"], req.to_dict())
        return t.OrgMembersResponse.from_dict(res or {})

    # -- org SSO connections ------------------------------------------------ #
    def create_org_oidc_connection(
        self, req: t.CreateOrgOIDCConnectionRequest
    ) -> t.OrgOIDCConnection:
        res = self._invoke(
            "create_org_oidc_connection", d.ADMIN["create_org_oidc_connection"], req.to_dict()
        )
        return t.OrgOIDCConnection.from_dict(res or {})

    def update_org_oidc_connection(
        self, req: t.UpdateOrgOIDCConnectionRequest
    ) -> t.OrgOIDCConnection:
        res = self._invoke(
            "update_org_oidc_connection", d.ADMIN["update_org_oidc_connection"], req.to_dict()
        )
        return t.OrgOIDCConnection.from_dict(res or {})

    def delete_org_oidc_connection(self, req: t.OrgOIDCConnectionRequest) -> t.GenericResponse:
        """Destructive: org members lose this OIDC SSO path."""
        res = self._invoke(
            "delete_org_oidc_connection", d.ADMIN["delete_org_oidc_connection"], req.to_dict()
        )
        return t.GenericResponse.from_dict(res or {})

    def get_org_oidc_connection(self, req: t.OrgOIDCConnectionRequest) -> t.OrgOIDCConnection:
        res = self._invoke(
            "get_org_oidc_connection", d.ADMIN["get_org_oidc_connection"], req.to_dict()
        )
        return t.OrgOIDCConnection.from_dict(res or {})

    def create_org_saml_connection(
        self, req: t.CreateOrgSAMLConnectionRequest
    ) -> t.OrgSAMLConnection:
        res = self._invoke(
            "create_org_saml_connection", d.ADMIN["create_org_saml_connection"], req.to_dict()
        )
        return t.OrgSAMLConnection.from_dict(res or {})

    def update_org_saml_connection(
        self, req: t.UpdateOrgSAMLConnectionRequest
    ) -> t.OrgSAMLConnection:
        res = self._invoke(
            "update_org_saml_connection", d.ADMIN["update_org_saml_connection"], req.to_dict()
        )
        return t.OrgSAMLConnection.from_dict(res or {})

    def delete_org_saml_connection(self, req: t.OrgSAMLConnectionRequest) -> t.GenericResponse:
        """Destructive: org members lose this SAML SSO path."""
        res = self._invoke(
            "delete_org_saml_connection", d.ADMIN["delete_org_saml_connection"], req.to_dict()
        )
        return t.GenericResponse.from_dict(res or {})

    def get_org_saml_connection(self, req: t.OrgSAMLConnectionRequest) -> t.OrgSAMLConnection:
        res = self._invoke(
            "get_org_saml_connection", d.ADMIN["get_org_saml_connection"], req.to_dict()
        )
        return t.OrgSAMLConnection.from_dict(res or {})

    # -- SAML IdP (Authorizer as Identity Provider for downstream SPs) ---- #
    def create_saml_service_provider(
        self, req: t.CreateSAMLServiceProviderRequest
    ) -> t.SAMLServiceProvider:
        res = self._invoke(
            "create_saml_service_provider",
            d.ADMIN["create_saml_service_provider"],
            req.to_dict(),
        )
        return t.SAMLServiceProvider.from_dict(res or {})

    def update_saml_service_provider(
        self, req: t.UpdateSAMLServiceProviderRequest
    ) -> t.SAMLServiceProvider:
        res = self._invoke(
            "update_saml_service_provider",
            d.ADMIN["update_saml_service_provider"],
            req.to_dict(),
        )
        return t.SAMLServiceProvider.from_dict(res or {})

    def delete_saml_service_provider(
        self, req: t.SAMLServiceProviderRequest
    ) -> t.GenericResponse:
        """Destructive: the downstream SP can no longer be issued assertions."""
        res = self._invoke(
            "delete_saml_service_provider",
            d.ADMIN["delete_saml_service_provider"],
            req.to_dict(),
        )
        return t.GenericResponse.from_dict(res or {})

    def get_saml_service_provider(
        self, req: t.SAMLServiceProviderRequest
    ) -> t.SAMLServiceProvider:
        res = self._invoke(
            "get_saml_service_provider", d.ADMIN["get_saml_service_provider"], req.to_dict()
        )
        return t.SAMLServiceProvider.from_dict(res or {})

    def list_saml_service_providers(
        self, req: t.ListSAMLServiceProvidersRequest
    ) -> t.SAMLServiceProvidersResponse:
        res = self._invoke(
            "list_saml_service_providers",
            d.ADMIN["list_saml_service_providers"],
            req.to_dict(),
        )
        return t.SAMLServiceProvidersResponse.from_dict(res or {})

    def rotate_saml_idp_cert(self, req: t.RotateSAMLIDPCertRequest) -> t.SAMLIDPKey:
        """Generates a new current signing keypair; the previous key stays "active"."""
        res = self._invoke(
            "rotate_saml_idp_cert", d.ADMIN["rotate_saml_idp_cert"], req.to_dict()
        )
        return t.SAMLIDPKey.from_dict(res or {})

    def retire_saml_idp_key(self, req: t.RetireSAMLIDPKeyRequest) -> t.GenericResponse:
        """Destructive: the key stops appearing in IdP metadata. Cannot retire the current key."""
        res = self._invoke(
            "retire_saml_idp_key", d.ADMIN["retire_saml_idp_key"], req.to_dict()
        )
        return t.GenericResponse.from_dict(res or {})

    def list_saml_idp_keys(self, req: t.ListSAMLIDPKeysRequest) -> list[t.SAMLIDPKey]:
        res = self._invoke("list_saml_idp_keys", d.ADMIN["list_saml_idp_keys"], req.to_dict())
        # GraphQL returns a bare list; REST/gRPC wrap it as {"saml_idp_keys": [...]}.
        items = res if isinstance(res, list) else (res or {}).get("saml_idp_keys", [])
        return [t.SAMLIDPKey.from_dict(x) for x in items if isinstance(x, dict)]

    def import_saml_sp_metadata(
        self, req: t.ImportSAMLSPMetadataRequest
    ) -> t.SAMLSPMetadataParseResult:
        """Parses pasted SP metadata XML; does NOT create a record or fetch a URL."""
        res = self._invoke(
            "import_saml_sp_metadata", d.ADMIN["import_saml_sp_metadata"], req.to_dict()
        )
        return t.SAMLSPMetadataParseResult.from_dict(res or {})

    # -- user organizations ------------------------------------------------- #
    def user_organizations(self, req: t.UserOrganizationsRequest) -> t.UserOrganizationsResponse:
        res = self._invoke("user_organizations", d.ADMIN["user_organizations"], req.to_dict())
        return t.UserOrganizationsResponse.from_dict(res or {})

    # -- org domains (home-realm discovery) ---------------------------------- #
    def request_org_domain(self, req: t.RequestOrgDomainRequest) -> t.OrgDomainChallenge:
        res = self._invoke("request_org_domain", d.ADMIN["request_org_domain"], req.to_dict())
        return t.OrgDomainChallenge.from_dict(res or {})

    def verify_org_domain(self, req: t.VerifyOrgDomainRequest) -> t.OrgDomain:
        res = self._invoke("verify_org_domain", d.ADMIN["verify_org_domain"], req.to_dict())
        return t.OrgDomain.from_dict(res or {})

    def add_verified_org_domain(self, req: t.AddVerifiedOrgDomainRequest) -> t.OrgDomain:
        """Super-admin only: trusted-asserts a domain as verified, skipping DNS challenge."""
        res = self._invoke(
            "add_verified_org_domain", d.ADMIN["add_verified_org_domain"], req.to_dict()
        )
        return t.OrgDomain.from_dict(res or {})

    def delete_org_domain(self, req: t.DeleteOrgDomainRequest) -> t.GenericResponse:
        """Destructive: the domain no longer routes logins to this organization."""
        res = self._invoke("delete_org_domain", d.ADMIN["delete_org_domain"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def org_domains(self, req: t.ListOrgDomainsRequest) -> t.OrgDomainsResponse:
        res = self._invoke("org_domains", d.ADMIN["org_domains"], req.to_dict())
        return t.OrgDomainsResponse.from_dict(res or {})

    # -- SCIM endpoints ------------------------------------------------------ #
    def create_scim_endpoint(
        self, req: t.CreateScimEndpointRequest
    ) -> t.CreateScimEndpointResponse:
        """The returned bearer token is shown ONCE and can never be retrieved again."""
        res = self._invoke("create_scim_endpoint", d.ADMIN["create_scim_endpoint"], req.to_dict())
        return t.CreateScimEndpointResponse.from_dict(res or {})

    def rotate_scim_token(self, req: t.ScimEndpointRequest) -> t.CreateScimEndpointResponse:
        """Destructive: invalidates the old token; the new one is shown ONCE."""
        res = self._invoke("rotate_scim_token", d.ADMIN["rotate_scim_token"], req.to_dict())
        return t.CreateScimEndpointResponse.from_dict(res or {})

    def delete_scim_endpoint(self, req: t.ScimEndpointRequest) -> t.GenericResponse:
        """Destructive: the org's SCIM provisioning stops working."""
        res = self._invoke("delete_scim_endpoint", d.ADMIN["delete_scim_endpoint"], req.to_dict())
        return t.GenericResponse.from_dict(res or {})

    def get_scim_endpoint(self, req: t.ScimEndpointRequest) -> t.ScimEndpoint:
        res = self._invoke("get_scim_endpoint", d.ADMIN["get_scim_endpoint"], req.to_dict())
        return t.ScimEndpoint.from_dict(res or {})
