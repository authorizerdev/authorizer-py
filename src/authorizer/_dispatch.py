"""Declarative per-method protocol descriptors shared by sync + async clients.

Each :class:`MethodSpec` says how one logical SDK method maps onto each of the
three transports (graphql / rest / grpc). The clients hold one dispatcher that
reads these specs, so adding a method or fixing a mapping happens in one place
and sync/async stay in lock-step.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import _queries as q


@dataclass(frozen=True)
class MethodSpec:
    protocols: tuple[str, ...]
    # graphql
    gql_query: str | None = None
    gql_field: str | None = None
    # rest
    rest_method: str | None = None
    rest_path: str | None = None
    rest_unwrap: str | None = None
    # grpc: stub attribute, request message name (in admin_pb2/authorizer_pb2),
    # and the response field to unwrap (None = whole message).
    grpc_method: str | None = None
    grpc_request: str | None = None
    grpc_response_unwrap: str | None = None
    # gql_flat_vars: True for the handful of GraphQL fields (webauthn_*
    # ceremonies) that take top-level scalar args instead of a single
    # ``params: X`` input object — see _core.prepare_http.
    gql_flat_vars: bool = False


ALL = ("graphql", "rest", "grpc")
GQL_ONLY = ("graphql",)


# --------------------------------------------------------------------------- #
# Public (user) service methods
# --------------------------------------------------------------------------- #
#
# Protocol availability (server 2.3.0, PR #635 + #636): ALL 20 public RPCs
# now work over graphql + rest + grpc. There are no graphql-only public methods.
# The response envelope is FLATTENED: the bare domain message is returned
# (Signup/Login/Session/VerifyEmail/VerifyOtp -> AuthResponse, Profile -> User,
# Meta -> Meta), so the auth/user/meta wrapper unwrapping is gone -- responses
# map directly onto the SDK dataclasses. ``_proto._response_message_cls`` resolves
# each RPC's output type from the service descriptor, so it tracks these flat types
# automatically. Field names are snake_case and byte-identical to GraphQL.
PUBLIC: dict[str, MethodSpec] = {
    "signup": MethodSpec(
        ALL, q.SIGNUP, "signup", "POST", "/v1/signup", None,
        "Signup", "SignupRequest", None,
    ),
    "login": MethodSpec(
        ALL, q.LOGIN, "login", "POST", "/v1/login", None,
        "Login", "LoginRequest", None,
    ),
    "magic_link_login": MethodSpec(
        ALL, q.MAGIC_LINK_LOGIN, "magic_link_login", "POST", "/v1/magic_link_login", None,
        "MagicLinkLogin", "MagicLinkLoginRequest", None,
    ),
    "verify_email": MethodSpec(
        ALL, q.VERIFY_EMAIL, "verify_email", "POST", "/v1/verify_email", None,
        "VerifyEmail", "VerifyEmailRequest", None,
    ),
    "resend_verify_email": MethodSpec(
        ALL, q.RESEND_VERIFY_EMAIL, "resend_verify_email",
        "POST", "/v1/resend_verify_email", None,
        "ResendVerifyEmail", "ResendVerifyEmailRequest", None,
    ),
    "verify_otp": MethodSpec(
        ALL, q.VERIFY_OTP, "verify_otp", "POST", "/v1/verify_otp", None,
        "VerifyOtp", "VerifyOtpRequest", None,
    ),
    "resend_otp": MethodSpec(
        ALL, q.RESEND_OTP, "resend_otp", "POST", "/v1/resend_otp", None,
        "ResendOtp", "ResendOtpRequest", None,
    ),
    "forgot_password": MethodSpec(
        ALL, q.FORGOT_PASSWORD, "forgot_password", "POST", "/v1/forgot_password", None,
        "ForgotPassword", "ForgotPasswordRequest", None,
    ),
    "reset_password": MethodSpec(
        ALL, q.RESET_PASSWORD, "reset_password", "POST", "/v1/reset_password", None,
        "ResetPassword", "ResetPasswordRequest", None,
    ),
    "update_profile": MethodSpec(
        ALL, q.UPDATE_PROFILE, "update_profile", "POST", "/v1/update_profile", None,
        "UpdateProfile", "UpdateProfileRequest", None,
    ),
    "deactivate_account": MethodSpec(
        ALL, q.DEACTIVATE_ACCOUNT, "deactivate_account", "POST", "/v1/deactivate_account", None,
        "DeactivateAccount", "DeactivateAccountRequest", None,
    ),
    "validate_jwt_token": MethodSpec(
        ALL, q.VALIDATE_JWT_TOKEN, "validate_jwt_token", "POST", "/v1/validate_jwt_token", None,
        "ValidateJwtToken", "ValidateJwtTokenRequest", None,
    ),
    "validate_session": MethodSpec(
        ALL, q.VALIDATE_SESSION, "validate_session", "POST", "/v1/validate_session", None,
        "ValidateSession", "ValidateSessionRequest", None,
    ),
    "meta": MethodSpec(
        ALL, q.META, "meta", "GET", "/v1/meta", None, "Meta", "MetaRequest", None
    ),
    "session": MethodSpec(
        ALL, q.SESSION, "session", "POST", "/v1/session", None,
        "Session", "SessionRequest", None,
    ),
    "profile": MethodSpec(
        ALL, q.PROFILE, "profile", "GET", "/v1/profile", None, "Profile", "ProfileRequest", None
    ),
    "logout": MethodSpec(
        ALL, q.LOGOUT, "logout", "POST", "/v1/logout", None, "Logout", "LogoutRequest", None
    ),
    "check_permissions": MethodSpec(
        ALL, q.CHECK_PERMISSIONS, "check_permissions", "POST", "/v1/check_permissions", None,
        "CheckPermissions", "CheckPermissionsRequest", None,
    ),
    "list_permissions": MethodSpec(
        ALL, q.LIST_PERMISSIONS, "list_permissions", "POST", "/v1/list_permissions", None,
        "ListPermissions", "ListPermissionsRequest", None,
    ),
    "skip_mfa_setup": MethodSpec(
        ALL, q.SKIP_MFA_SETUP, "skip_mfa_setup", "POST", "/v1/skip_mfa_setup", None,
        "SkipMfaSetup", "SkipMfaSetupRequest", None,
    ),
    "lock_mfa": MethodSpec(
        ALL, q.LOCK_MFA, "lock_mfa", "POST", "/v1/lock_mfa", None,
        "LockMfa", "LockMfaRequest", None,
    ),
    "email_otp_mfa_setup": MethodSpec(
        ALL, q.EMAIL_OTP_MFA_SETUP, "email_otp_mfa_setup",
        "POST", "/v1/email_otp_mfa_setup", None,
        "EmailOtpMfaSetup", "EmailOtpMfaSetupRequest", None,
    ),
    "sms_otp_mfa_setup": MethodSpec(
        ALL, q.SMS_OTP_MFA_SETUP, "sms_otp_mfa_setup", "POST", "/v1/sms_otp_mfa_setup", None,
        "SmsOtpMfaSetup", "SmsOtpMfaSetupRequest", None,
    ),
    # WebAuthn/passkeys + TOTP setup: graphql-only on the server (no proto RPC).
    "totp_mfa_setup": MethodSpec(
        ALL, q.TOTP_MFA_SETUP, "totp_mfa_setup", "POST", "/v1/totp_mfa_setup", None,
        "TotpMfaSetup", "TotpMfaSetupRequest", None,
    ),
    "webauthn_registration_options": MethodSpec(
        ALL, q.WEBAUTHN_REGISTRATION_OPTIONS, "webauthn_registration_options",
        "POST", "/v1/webauthn_registration_options", None,
        "WebauthnRegistrationOptions", "WebauthnRegistrationOptionsRequest", None,
        gql_flat_vars=True,
    ),
    "webauthn_registration_verify": MethodSpec(
        ALL, q.WEBAUTHN_REGISTRATION_VERIFY, "webauthn_registration_verify",
        "POST", "/v1/webauthn_registration_verify", None,
        "WebauthnRegistrationVerify", "WebauthnRegistrationVerifyRequest", None,
    ),
    "webauthn_login_options": MethodSpec(
        ALL, q.WEBAUTHN_LOGIN_OPTIONS, "webauthn_login_options",
        "POST", "/v1/webauthn_login_options", None,
        "WebauthnLoginOptions", "WebauthnLoginOptionsRequest", None,
        gql_flat_vars=True,
    ),
    "webauthn_login_verify": MethodSpec(
        ALL, q.WEBAUTHN_LOGIN_VERIFY, "webauthn_login_verify",
        "POST", "/v1/webauthn_login_verify", None,
        "WebauthnLoginVerify", "WebauthnLoginVerifyRequest", None,
    ),
    "webauthn_delete_credential": MethodSpec(
        ALL, q.WEBAUTHN_DELETE_CREDENTIAL, "webauthn_delete_credential",
        "POST", "/v1/webauthn_delete_credential", None,
        "WebauthnDeleteCredential", "WebauthnDeleteCredentialRequest", None,
        gql_flat_vars=True,
    ),
    "webauthn_credentials": MethodSpec(
        ALL, q.WEBAUTHN_CREDENTIALS, "webauthn_credentials",
        "POST", "/v1/webauthn_credentials", "webauthn_credentials",
        "WebauthnCredentials", "WebauthnCredentialsRequest", "webauthn_credentials",
    ),
}


# --------------------------------------------------------------------------- #
# Admin service methods. ``rest_unwrap``/``grpc_response_unwrap`` name the single
# nested message on the response (None when the response is flat: a ``message``
# string or a paginated list the dataclass reads whole).
# --------------------------------------------------------------------------- #
ADMIN: dict[str, MethodSpec] = {
    "admin_login": MethodSpec(
        ALL, q.ADMIN_LOGIN, "_admin_login", "POST", "/v1/admin/login", None,
        "AdminLogin", "AdminLoginRequest", None,
    ),
    "admin_logout": MethodSpec(
        ALL, q.ADMIN_LOGOUT, "_admin_logout", "POST", "/v1/admin/logout", None,
        "AdminLogout", "AdminLogoutRequest", None,
    ),
    "admin_session": MethodSpec(
        ALL, q.ADMIN_SESSION, "_admin_session", "GET", "/v1/admin/session", None,
        "AdminSession", "AdminSessionRequest", None,
    ),
    "admin_meta": MethodSpec(
        ALL, q.ADMIN_META, "_admin_meta", "GET", "/v1/admin/meta", "admin_meta",
        "AdminMeta", "AdminMetaRequest", "admin_meta",
    ),
    "users": MethodSpec(
        ALL, q.ADMIN_USERS, "_users", "POST", "/v1/admin/users", None,
        "Users", "UsersRequest", None,
    ),
    "user": MethodSpec(
        ALL, q.ADMIN_USER, "_user", "POST", "/v1/admin/user", "user",
        "User", "UserRequest", "user",
    ),
    "update_user": MethodSpec(
        ALL, q.ADMIN_UPDATE_USER, "_update_user", "POST", "/v1/admin/update_user", "user",
        "UpdateUser", "UpdateUserRequest", "user",
    ),
    "delete_user": MethodSpec(
        ALL, q.ADMIN_DELETE_USER, "_delete_user", "POST", "/v1/admin/delete_user", None,
        "DeleteUser", "DeleteUserRequest", None,
    ),
    "verification_requests": MethodSpec(
        ALL, q.ADMIN_VERIFICATION_REQUESTS, "_verification_requests",
        "POST", "/v1/admin/verification_requests", None,
        "VerificationRequests", "VerificationRequestsRequest", None,
    ),
    "revoke_access": MethodSpec(
        ALL, q.ADMIN_REVOKE_ACCESS, "_revoke_access", "POST", "/v1/admin/revoke_access", None,
        "RevokeAccess", "RevokeAccessRequest", None,
    ),
    "enable_access": MethodSpec(
        ALL, q.ADMIN_ENABLE_ACCESS, "_enable_access", "POST", "/v1/admin/enable_access", None,
        "EnableAccess", "EnableAccessRequest", None,
    ),
    "invite_members": MethodSpec(
        ALL, q.ADMIN_INVITE_MEMBERS, "_invite_members", "POST", "/v1/admin/invite_members", None,
        "InviteMembers", "InviteMembersRequest", None,
    ),
    "add_webhook": MethodSpec(
        ALL, q.ADMIN_ADD_WEBHOOK, "_add_webhook", "POST", "/v1/admin/add_webhook", None,
        "AddWebhook", "AddWebhookRequest", None,
    ),
    "update_webhook": MethodSpec(
        ALL, q.ADMIN_UPDATE_WEBHOOK, "_update_webhook", "POST", "/v1/admin/update_webhook", None,
        "UpdateWebhook", "UpdateWebhookRequest", None,
    ),
    "delete_webhook": MethodSpec(
        ALL, q.ADMIN_DELETE_WEBHOOK, "_delete_webhook", "POST", "/v1/admin/delete_webhook", None,
        "DeleteWebhook", "DeleteWebhookRequest", None,
    ),
    "get_webhook": MethodSpec(
        ALL, q.ADMIN_GET_WEBHOOK, "_webhook", "POST", "/v1/admin/webhook", "webhook",
        "GetWebhook", "GetWebhookRequest", "webhook",
    ),
    "webhooks": MethodSpec(
        ALL, q.ADMIN_WEBHOOKS, "_webhooks", "POST", "/v1/admin/webhooks", None,
        "Webhooks", "WebhooksRequest", None,
    ),
    "webhook_logs": MethodSpec(
        ALL, q.ADMIN_WEBHOOK_LOGS, "_webhook_logs", "POST", "/v1/admin/webhook_logs", None,
        "WebhookLogs", "WebhookLogsRequest", None,
    ),
    "test_endpoint": MethodSpec(
        ALL, q.ADMIN_TEST_ENDPOINT, "_test_endpoint", "POST", "/v1/admin/test_endpoint", None,
        "TestEndpoint", "TestEndpointRequest", None,
    ),
    "add_email_template": MethodSpec(
        ALL, q.ADMIN_ADD_EMAIL_TEMPLATE, "_add_email_template",
        "POST", "/v1/admin/add_email_template", None,
        "AddEmailTemplate", "AddEmailTemplateRequest", None,
    ),
    "update_email_template": MethodSpec(
        ALL, q.ADMIN_UPDATE_EMAIL_TEMPLATE, "_update_email_template",
        "POST", "/v1/admin/update_email_template", None,
        "UpdateEmailTemplate", "UpdateEmailTemplateRequest", None,
    ),
    "delete_email_template": MethodSpec(
        ALL, q.ADMIN_DELETE_EMAIL_TEMPLATE, "_delete_email_template",
        "POST", "/v1/admin/delete_email_template", None,
        "DeleteEmailTemplate", "DeleteEmailTemplateRequest", None,
    ),
    "email_templates": MethodSpec(
        ALL, q.ADMIN_EMAIL_TEMPLATES, "_email_templates", "POST", "/v1/admin/email_templates", None,
        "EmailTemplates", "EmailTemplatesRequest", None,
    ),
    "audit_logs": MethodSpec(
        ALL, q.ADMIN_AUDIT_LOGS, "_audit_logs", "POST", "/v1/admin/audit_logs", None,
        "AuditLogs", "AuditLogsRequest", None,
    ),
    "fga_get_model": MethodSpec(
        ALL, q.ADMIN_FGA_GET_MODEL, "_fga_get_model", "GET", "/v1/admin/fga/model", "model",
        "FgaGetModel", "FgaGetModelRequest", "model",
    ),
    "fga_write_model": MethodSpec(
        ALL, q.ADMIN_FGA_WRITE_MODEL, "_fga_write_model", "POST", "/v1/admin/fga/model", "model",
        "FgaWriteModel", "FgaWriteModelRequest", "model",
    ),
    "fga_write_tuples": MethodSpec(
        ALL, q.ADMIN_FGA_WRITE_TUPLES, "_fga_write_tuples", "POST", "/v1/admin/fga/tuples", None,
        "FgaWriteTuples", "FgaWriteTuplesRequest", None,
    ),
    "fga_delete_tuples": MethodSpec(
        ALL, q.ADMIN_FGA_DELETE_TUPLES, "_fga_delete_tuples",
        "POST", "/v1/admin/fga/tuples/delete", None,
        "FgaDeleteTuples", "FgaDeleteTuplesRequest", None,
    ),
    "fga_read_tuples": MethodSpec(
        ALL, q.ADMIN_FGA_READ_TUPLES, "_fga_read_tuples", "POST", "/v1/admin/fga/tuples/read", None,
        "FgaReadTuples", "FgaReadTuplesRequest", None,
    ),
    "fga_list_users": MethodSpec(
        ALL, q.ADMIN_FGA_LIST_USERS, "_fga_list_users", "POST", "/v1/admin/fga/list_users", None,
        "FgaListUsers", "FgaListUsersRequest", None,
    ),
    "fga_expand": MethodSpec(
        ALL, q.ADMIN_FGA_EXPAND, "_fga_expand", "POST", "/v1/admin/fga/expand", None,
        "FgaExpand", "FgaExpandRequest", None,
    ),
    "fga_reset": MethodSpec(
        ALL, q.ADMIN_FGA_RESET, "_fga_reset", "POST", "/v1/admin/fga/reset", None,
        "FgaReset", "FgaResetRequest", None,
    ),
    # gql-only extras (no proto / no rest / no grpc).
    "admin_signup": MethodSpec(GQL_ONLY, q.ADMIN_SIGNUP, "_admin_signup"),
    "update_env": MethodSpec(GQL_ONLY, q.ADMIN_UPDATE_ENV, "_update_env"),
    "generate_jwt_keys": MethodSpec(GQL_ONLY, q.ADMIN_GENERATE_JWT_KEYS, "_generate_jwt_keys"),
    # Machine-agent-identity ops. Orgs/SSO/SCIM/user_organizations/org_domains
    # are graphql-only on the server. Clients + trusted issuers DO have proto
    # RPCs server-side and the vendored stubs now carry them (re-vendored from
    # proto/buf.gen.clients.yaml at server HEAD ca628cee) -- ALL 3 protocols.
    # CreateClientResponse/RotateClientSecretRequest->CreateClientResponse carry
    # TWO top-level fields (client, client_secret) -- unwrap=None, whole message.
    "create_client": MethodSpec(
        ALL, q.ADMIN_CREATE_CLIENT, "_create_client", "POST", "/v1/admin/create_client", None,
        "CreateClient", "CreateClientRequest", None,
    ),
    "update_client": MethodSpec(
        ALL, q.ADMIN_UPDATE_CLIENT, "_update_client", "POST", "/v1/admin/update_client", "client",
        "UpdateClient", "UpdateClientRequest", "client",
    ),
    "delete_client": MethodSpec(
        ALL, q.ADMIN_DELETE_CLIENT, "_delete_client", "POST", "/v1/admin/delete_client", None,
        "DeleteClient", "DeleteClientRequest", None,
    ),
    "rotate_client_secret": MethodSpec(
        ALL, q.ADMIN_ROTATE_CLIENT_SECRET, "_rotate_client_secret",
        "POST", "/v1/admin/rotate_client_secret", None,
        "RotateClientSecret", "RotateClientSecretRequest", None,
    ),
    "get_client": MethodSpec(
        ALL, q.ADMIN_GET_CLIENT, "_client", "POST", "/v1/admin/client", "client",
        "GetClient", "GetClientRequest", "client",
    ),
    "clients": MethodSpec(
        ALL, q.ADMIN_CLIENTS, "_clients", "POST", "/v1/admin/clients", None,
        "Clients", "ClientsRequest", None,
    ),
    "add_trusted_issuer": MethodSpec(
        ALL, q.ADMIN_ADD_TRUSTED_ISSUER, "_add_trusted_issuer",
        "POST", "/v1/admin/add_trusted_issuer", "trusted_issuer",
        "AddTrustedIssuer", "AddTrustedIssuerRequest", "trusted_issuer",
    ),
    "update_trusted_issuer": MethodSpec(
        ALL, q.ADMIN_UPDATE_TRUSTED_ISSUER, "_update_trusted_issuer",
        "POST", "/v1/admin/update_trusted_issuer", "trusted_issuer",
        "UpdateTrustedIssuer", "UpdateTrustedIssuerRequest", "trusted_issuer",
    ),
    "delete_trusted_issuer": MethodSpec(
        ALL, q.ADMIN_DELETE_TRUSTED_ISSUER, "_delete_trusted_issuer",
        "POST", "/v1/admin/delete_trusted_issuer", None,
        "DeleteTrustedIssuer", "DeleteTrustedIssuerRequest", None,
    ),
    "get_trusted_issuer": MethodSpec(
        ALL, q.ADMIN_GET_TRUSTED_ISSUER, "_trusted_issuer",
        "POST", "/v1/admin/trusted_issuer", "trusted_issuer",
        "GetTrustedIssuer", "GetTrustedIssuerRequest", "trusted_issuer",
    ),
    "trusted_issuers": MethodSpec(
        ALL, q.ADMIN_TRUSTED_ISSUERS, "_trusted_issuers",
        "POST", "/v1/admin/trusted_issuers", None,
        "TrustedIssuers", "TrustedIssuersRequest", None,
    ),
    # SAML IdP (Authorizer as Identity Provider for downstream SPs).
    "create_saml_service_provider": MethodSpec(
        ALL, q.ADMIN_CREATE_SAML_SERVICE_PROVIDER, "_create_saml_service_provider",
        "POST", "/v1/admin/create_saml_service_provider", "saml_service_provider",
        "CreateSamlServiceProvider", "CreateSamlServiceProviderRequest", "saml_service_provider",
    ),
    "update_saml_service_provider": MethodSpec(
        ALL, q.ADMIN_UPDATE_SAML_SERVICE_PROVIDER, "_update_saml_service_provider",
        "POST", "/v1/admin/update_saml_service_provider", "saml_service_provider",
        "UpdateSamlServiceProvider", "UpdateSamlServiceProviderRequest", "saml_service_provider",
    ),
    "delete_saml_service_provider": MethodSpec(
        ALL, q.ADMIN_DELETE_SAML_SERVICE_PROVIDER, "_delete_saml_service_provider",
        "POST", "/v1/admin/delete_saml_service_provider", None,
        "DeleteSamlServiceProvider", "DeleteSamlServiceProviderRequest", None,
    ),
    "get_saml_service_provider": MethodSpec(
        ALL, q.ADMIN_GET_SAML_SERVICE_PROVIDER, "_saml_service_provider",
        "POST", "/v1/admin/saml_service_provider", "saml_service_provider",
        "GetSamlServiceProvider", "GetSamlServiceProviderRequest", "saml_service_provider",
    ),
    "list_saml_service_providers": MethodSpec(
        ALL, q.ADMIN_LIST_SAML_SERVICE_PROVIDERS, "_list_saml_service_providers",
        "POST", "/v1/admin/saml_service_providers", None,
        "ListSamlServiceProviders", "ListSamlServiceProvidersRequest", None,
    ),
    "rotate_saml_idp_cert": MethodSpec(
        ALL, q.ADMIN_ROTATE_SAML_IDP_CERT, "_rotate_saml_idp_cert",
        "POST", "/v1/admin/rotate_saml_idp_cert", "saml_idp_key",
        "RotateSamlIdpCert", "RotateSamlIdpCertRequest", "saml_idp_key",
    ),
    "retire_saml_idp_key": MethodSpec(
        ALL, q.ADMIN_RETIRE_SAML_IDP_KEY, "_retire_saml_idp_key",
        "POST", "/v1/admin/retire_saml_idp_key", None,
        "RetireSamlIdpKey", "RetireSamlIdpKeyRequest", None,
    ),
    "list_saml_idp_keys": MethodSpec(
        ALL, q.ADMIN_LIST_SAML_IDP_KEYS, "_list_saml_idp_keys",
        "POST", "/v1/admin/saml_idp_keys", None,
        "ListSamlIdpKeys", "ListSamlIdpKeysRequest", None,
    ),
    "import_saml_sp_metadata": MethodSpec(
        ALL, q.ADMIN_IMPORT_SAML_SP_METADATA, "_import_saml_sp_metadata",
        "POST", "/v1/admin/import_saml_sp_metadata", "result",
        "ImportSamlSpMetadata", "ImportSamlSpMetadataRequest", "result",
    ),
    # user_organizations / org domains: graphql-only on the server (no proto RPC).
    "user_organizations": MethodSpec(
        ALL, q.ADMIN_USER_ORGANIZATIONS, "_user_organizations",
        "POST", "/v1/admin/user_organizations", None,
        "UserOrganizations", "UserOrganizationsRequest", None,
    ),
    "request_org_domain": MethodSpec(
        ALL, q.ADMIN_REQUEST_ORG_DOMAIN, "_request_org_domain",
        "POST", "/v1/admin/request_org_domain", "challenge",
        "RequestOrgDomain", "RequestOrgDomainRequest", "challenge",
    ),
    "verify_org_domain": MethodSpec(
        ALL, q.ADMIN_VERIFY_ORG_DOMAIN, "_verify_org_domain",
        "POST", "/v1/admin/verify_org_domain", "org_domain",
        "VerifyOrgDomain", "VerifyOrgDomainRequest", "org_domain",
    ),
    "add_verified_org_domain": MethodSpec(
        ALL, q.ADMIN_ADD_VERIFIED_ORG_DOMAIN, "_add_verified_org_domain",
        "POST", "/v1/admin/add_verified_org_domain", "org_domain",
        "AddVerifiedOrgDomain", "AddVerifiedOrgDomainRequest", "org_domain",
    ),
    "delete_org_domain": MethodSpec(
        ALL, q.ADMIN_DELETE_ORG_DOMAIN, "_delete_org_domain",
        "POST", "/v1/admin/delete_org_domain", None,
        "DeleteOrgDomain", "DeleteOrgDomainRequest", None,
    ),
    "org_domains": MethodSpec(
        ALL, q.ADMIN_ORG_DOMAINS, "_org_domains", "POST", "/v1/admin/org_domains", None,
        "OrgDomains", "OrgDomainsRequest", None,
    ),
    "create_organization": MethodSpec(
        ALL, q.ADMIN_CREATE_ORGANIZATION, "_create_organization",
        "POST", "/v1/admin/create_organization", "organization",
        "CreateOrganization", "CreateOrganizationRequest", "organization",
    ),
    "update_organization": MethodSpec(
        ALL, q.ADMIN_UPDATE_ORGANIZATION, "_update_organization",
        "POST", "/v1/admin/update_organization", "organization",
        "UpdateOrganization", "UpdateOrganizationRequest", "organization",
    ),
    "delete_organization": MethodSpec(
        ALL, q.ADMIN_DELETE_ORGANIZATION, "_delete_organization",
        "POST", "/v1/admin/delete_organization", None,
        "DeleteOrganization", "DeleteOrganizationRequest", None,
    ),
    "add_org_member": MethodSpec(
        ALL, q.ADMIN_ADD_ORG_MEMBER, "_add_org_member",
        "POST", "/v1/admin/add_org_member", "org_member",
        "AddOrgMember", "AddOrgMemberRequest", "org_member",
    ),
    "remove_org_member": MethodSpec(
        ALL, q.ADMIN_REMOVE_ORG_MEMBER, "_remove_org_member",
        "POST", "/v1/admin/remove_org_member", None,
        "RemoveOrgMember", "RemoveOrgMemberRequest", None,
    ),
    "get_organization": MethodSpec(
        ALL, q.ADMIN_GET_ORGANIZATION, "_organization",
        "POST", "/v1/admin/organization", "organization",
        "GetOrganization", "GetOrganizationRequest", "organization",
    ),
    "organizations": MethodSpec(
        ALL, q.ADMIN_ORGANIZATIONS, "_organizations", "POST", "/v1/admin/organizations", None,
        "Organizations", "OrganizationsRequest", None,
    ),
    "org_members": MethodSpec(
        ALL, q.ADMIN_ORG_MEMBERS, "_org_members", "POST", "/v1/admin/org_members", None,
        "OrgMembers", "OrgMembersRequest", None,
    ),
    "create_org_oidc_connection": MethodSpec(
        ALL, q.ADMIN_CREATE_ORG_OIDC_CONNECTION, "_create_org_oidc_connection",
        "POST", "/v1/admin/create_org_oidc_connection", "org_oidc_connection",
        "CreateOrgOidcConnection", "CreateOrgOidcConnectionRequest", "org_oidc_connection",
    ),
    "update_org_oidc_connection": MethodSpec(
        ALL, q.ADMIN_UPDATE_ORG_OIDC_CONNECTION, "_update_org_oidc_connection",
        "POST", "/v1/admin/update_org_oidc_connection", "org_oidc_connection",
        "UpdateOrgOidcConnection", "UpdateOrgOidcConnectionRequest", "org_oidc_connection",
    ),
    "delete_org_oidc_connection": MethodSpec(
        ALL, q.ADMIN_DELETE_ORG_OIDC_CONNECTION, "_delete_org_oidc_connection",
        "POST", "/v1/admin/delete_org_oidc_connection", None,
        "DeleteOrgOidcConnection", "DeleteOrgOidcConnectionRequest", None,
    ),
    "get_org_oidc_connection": MethodSpec(
        ALL, q.ADMIN_GET_ORG_OIDC_CONNECTION, "_org_oidc_connection",
        "POST", "/v1/admin/org_oidc_connection", "org_oidc_connection",
        "GetOrgOidcConnection", "GetOrgOidcConnectionRequest", "org_oidc_connection",
    ),
    "create_org_saml_connection": MethodSpec(
        ALL, q.ADMIN_CREATE_ORG_SAML_CONNECTION, "_create_org_saml_connection",
        "POST", "/v1/admin/create_org_saml_connection", "org_saml_connection",
        "CreateOrgSamlConnection", "CreateOrgSamlConnectionRequest", "org_saml_connection",
    ),
    "update_org_saml_connection": MethodSpec(
        ALL, q.ADMIN_UPDATE_ORG_SAML_CONNECTION, "_update_org_saml_connection",
        "POST", "/v1/admin/update_org_saml_connection", "org_saml_connection",
        "UpdateOrgSamlConnection", "UpdateOrgSamlConnectionRequest", "org_saml_connection",
    ),
    "delete_org_saml_connection": MethodSpec(
        ALL, q.ADMIN_DELETE_ORG_SAML_CONNECTION, "_delete_org_saml_connection",
        "POST", "/v1/admin/delete_org_saml_connection", None,
        "DeleteOrgSamlConnection", "DeleteOrgSamlConnectionRequest", None,
    ),
    "get_org_saml_connection": MethodSpec(
        ALL, q.ADMIN_GET_ORG_SAML_CONNECTION, "_org_saml_connection",
        "POST", "/v1/admin/org_saml_connection", "org_saml_connection",
        "GetOrgSamlConnection", "GetOrgSamlConnectionRequest", "org_saml_connection",
    ),
    "create_scim_endpoint": MethodSpec(
        ALL, q.ADMIN_CREATE_SCIM_ENDPOINT, "_create_scim_endpoint",
        "POST", "/v1/admin/create_scim_endpoint", None,
        "CreateScimEndpoint", "CreateScimEndpointRequest", None,
    ),
    "rotate_scim_token": MethodSpec(
        ALL, q.ADMIN_ROTATE_SCIM_TOKEN, "_rotate_scim_token",
        "POST", "/v1/admin/rotate_scim_token", None,
        "RotateScimToken", "RotateScimTokenRequest", None,
    ),
    "delete_scim_endpoint": MethodSpec(
        ALL, q.ADMIN_DELETE_SCIM_ENDPOINT, "_delete_scim_endpoint",
        "POST", "/v1/admin/delete_scim_endpoint", None,
        "DeleteScimEndpoint", "DeleteScimEndpointRequest", None,
    ),
    "get_scim_endpoint": MethodSpec(
        ALL, q.ADMIN_GET_SCIM_ENDPOINT, "_scim_endpoint",
        "POST", "/v1/admin/scim_endpoint", "scim_endpoint",
        "GetScimEndpoint", "GetScimEndpointRequest", "scim_endpoint",
    ),
}
