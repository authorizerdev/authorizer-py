"""GraphQL fragments and query/mutation strings used by the SDK.

Mirrors the queries in authorizer-go so server behavior is identical.
"""

from __future__ import annotations

USER_FRAGMENT = (
    "id email email_verified given_name family_name middle_name nickname "
    "preferred_username picture signup_methods gender birthdate phone_number "
    "phone_number_verified roles created_at updated_at is_multi_factor_auth_enabled "
    "app_data revoked_timestamp has_skipped_mfa_setup_at mfa_locked_at enrolled_mfa_methods"
)

AUTH_TOKEN_FRAGMENT = (
    "message access_token expires_in refresh_token id_token "
    "should_show_email_otp_screen should_show_mobile_otp_screen should_show_totp_screen "
    "should_offer_webauthn_mfa_verify should_offer_webauthn_mfa_setup "
    "should_offer_email_otp_mfa_setup should_offer_sms_otp_mfa_setup "
    "authenticator_scanner_image authenticator_secret authenticator_recovery_codes "
    f"user {{ {USER_FRAGMENT} }}"
)

LOGIN = (
    "mutation login($data: LoginRequest!) "
    f"{{ login(params: $data) {{ {AUTH_TOKEN_FRAGMENT} }} }}"
)

SIGNUP = (
    "mutation signup($data: SignUpRequest!) "
    f"{{ signup(params: $data) {{ {AUTH_TOKEN_FRAGMENT} }} }}"
)

MAGIC_LINK_LOGIN = (
    "mutation magicLinkLogin($data: MagicLinkLoginRequest!) "
    "{ magic_link_login(params: $data) { message } }"
)

VERIFY_OTP = (
    "mutation verifyOtp($data: VerifyOTPRequest!) "
    f"{{ verify_otp(params: $data) {{ {AUTH_TOKEN_FRAGMENT} }} }}"
)

VERIFY_EMAIL = (
    "mutation verifyEmail($data: VerifyEmailRequest!) "
    f"{{ verify_email(params: $data) {{ {AUTH_TOKEN_FRAGMENT} }} }}"
)

RESEND_OTP = (
    "mutation resendOtp($data: ResendOTPRequest!) { resend_otp(params: $data) { message } }"
)

RESEND_VERIFY_EMAIL = (
    "mutation resendVerifyEmail($data: ResendVerifyEmailRequest!) "
    "{ resend_verify_email(params: $data) { message } }"
)

FORGOT_PASSWORD = (
    "mutation forgotPassword($data: ForgotPasswordRequest!) "
    "{ forgot_password(params: $data) { message should_show_mobile_otp_screen } }"
)

RESET_PASSWORD = (
    "mutation resetPassword($data: ResetPasswordRequest!) "
    "{ reset_password(params: $data) { message } }"
)

VALIDATE_JWT_TOKEN = (
    "query validateJWTToken($data: ValidateJWTTokenRequest!)"
    "{ validate_jwt_token(params: $data) { is_valid claims } }"
)

VALIDATE_SESSION = (
    "query validateSession($data: ValidateSessionRequest!)"
    f"{{ validate_session(params: $data) {{ is_valid user {{ {USER_FRAGMENT} }} }} }}"
)

META = (
    "query { meta { version client_id is_google_login_enabled is_facebook_login_enabled "
    "is_github_login_enabled is_linkedin_login_enabled is_apple_login_enabled "
    "is_twitter_login_enabled is_discord_login_enabled is_microsoft_login_enabled "
    "is_twitch_login_enabled is_roblox_login_enabled is_email_verification_enabled "
    "is_basic_authentication_enabled is_magic_link_login_enabled is_sign_up_enabled "
    "is_strong_password_enabled is_multi_factor_auth_enabled "
    "is_mobile_basic_authentication_enabled is_phone_verification_enabled } }"
)

SESSION = (
    "query getSession($data: SessionQueryRequest) "
    f"{{ session(params: $data) {{ {AUTH_TOKEN_FRAGMENT} }} }}"
)

PROFILE = f"query {{ profile {{ {USER_FRAGMENT} }} }}"

UPDATE_PROFILE = (
    "mutation updateProfile($data: UpdateProfileRequest!) "
    "{ update_profile(params: $data) { message } }"
)

LOGOUT = "mutation { logout { message } }"

DEACTIVATE_ACCOUNT = "mutation deactivateAccount { deactivate_account { message } }"

CHECK_PERMISSIONS = (
    "query checkPermissions($data: CheckPermissionsInput!)"
    "{ check_permissions(params: $data) { results { relation object allowed } } }"
)

LIST_PERMISSIONS = (
    "query listPermissions($data: ListPermissionsInput!)"
    "{ list_permissions(params: $data) { objects permissions { object relation } truncated } }"
)

# -- MFA setup / recovery ----------------------------------------------------- #
SKIP_MFA_SETUP = (
    "mutation skipMfaSetup($data: SkipMfaSetupRequest!) "
    f"{{ skip_mfa_setup(params: $data) {{ {AUTH_TOKEN_FRAGMENT} }} }}"
)
LOCK_MFA = "mutation lockMfa($data: LockMfaRequest!) { lock_mfa(params: $data) { message } }"
EMAIL_OTP_MFA_SETUP = (
    "mutation emailOtpMfaSetup($data: OtpMfaSetupRequest) "
    "{ email_otp_mfa_setup(params: $data) { message } }"
)
SMS_OTP_MFA_SETUP = (
    "mutation smsOtpMfaSetup($data: OtpMfaSetupRequest) "
    "{ sms_otp_mfa_setup(params: $data) { message } }"
)
TOTP_MFA_SETUP = (
    "mutation totpMfaSetup($data: OtpMfaSetupRequest) "
    f"{{ totp_mfa_setup(params: $data) {{ {AUTH_TOKEN_FRAGMENT} }} }}"
)

# -- WebAuthn / passkeys ------------------------------------------------------- #
WEBAUTHN_CREDENTIAL_FRAGMENT = "id name transports created_at updated_at last_used_at"

WEBAUTHN_REGISTRATION_OPTIONS = (
    "mutation webauthnRegistrationOptions($email: String, $phone_number: String) "
    "{ webauthn_registration_options(email: $email, phone_number: $phone_number) "
    "{ options } }"
)
WEBAUTHN_REGISTRATION_VERIFY = (
    "mutation webauthnRegistrationVerify($data: WebauthnRegistrationVerifyRequest!) "
    f"{{ webauthn_registration_verify(params: $data) {{ {AUTH_TOKEN_FRAGMENT} }} }}"
)
WEBAUTHN_LOGIN_OPTIONS = (
    "mutation webauthnLoginOptions($email: String) "
    "{ webauthn_login_options(email: $email) { options } }"
)
WEBAUTHN_LOGIN_VERIFY = (
    "mutation webauthnLoginVerify($data: WebauthnLoginVerifyRequest!) "
    f"{{ webauthn_login_verify(params: $data) {{ {AUTH_TOKEN_FRAGMENT} }} }}"
)
WEBAUTHN_DELETE_CREDENTIAL = (
    "mutation webauthnDeleteCredential($id: ID!) "
    "{ webauthn_delete_credential(id: $id) { message } }"
)
WEBAUTHN_CREDENTIALS = f"query {{ webauthn_credentials {{ {WEBAUTHN_CREDENTIAL_FRAGMENT} }} }}"

# --------------------------------------------------------------------------- #
# Admin (`_`-prefixed) operations. GraphQL fragments mirror the admin schema.
# --------------------------------------------------------------------------- #
RESPONSE_FRAGMENT = "message"
PAGINATION_FRAGMENT = "pagination { limit page offset total }"
WEBHOOK_FRAGMENT = (
    "id event_name event_description endpoint enabled headers created_at updated_at"
)
WEBHOOK_LOG_FRAGMENT = "id http_status response request webhook_id created_at updated_at"
EMAIL_TEMPLATE_FRAGMENT = "id event_name template design subject created_at updated_at"
AUDIT_LOG_FRAGMENT = (
    "id actor_id actor_type actor_email action resource_type resource_id "
    "ip_address user_agent metadata created_at"
)
VERIFICATION_REQUEST_FRAGMENT = (
    "id identifier token email expires created_at updated_at nonce redirect_uri"
)

ADMIN_LOGIN = (
    "mutation adminLogin($data: AdminLoginRequest!) "
    "{ _admin_login(params: $data) { message } }"
)
ADMIN_SIGNUP = (
    "mutation adminSignup($data: AdminSignupRequest!) "
    "{ _admin_signup(params: $data) { message } }"
)
ADMIN_USERS = (
    "query adminUsers($data: ListUsersRequest) "
    f"{{ _users(params: $data) {{ {PAGINATION_FRAGMENT} users {{ {USER_FRAGMENT} }} }} }}"
)
ADMIN_USER = (
    "query adminUser($data: GetUserRequest!) "
    f"{{ _user(params: $data) {{ {USER_FRAGMENT} }} }}"
)
ADMIN_UPDATE_USER = (
    "mutation adminUpdateUser($data: UpdateUserRequest!) "
    f"{{ _update_user(params: $data) {{ {USER_FRAGMENT} }} }}"
)
ADMIN_DELETE_USER = (
    "mutation adminDeleteUser($data: DeleteUserRequest!) "
    "{ _delete_user(params: $data) { message } }"
)
ADMIN_VERIFICATION_REQUESTS = (
    "query adminVerificationRequests($data: PaginationRequest) "
    f"{{ _verification_requests(params: $data) {{ {PAGINATION_FRAGMENT} "
    f"verification_requests {{ {VERIFICATION_REQUEST_FRAGMENT} }} }} }}"
)
ADMIN_REVOKE_ACCESS = (
    "mutation adminRevokeAccess($data: UpdateAccessRequest!) "
    "{ _revoke_access(param: $data) { message } }"
)
ADMIN_ENABLE_ACCESS = (
    "mutation adminEnableAccess($data: UpdateAccessRequest!) "
    "{ _enable_access(param: $data) { message } }"
)
ADMIN_INVITE_MEMBERS = (
    "mutation adminInviteMembers($data: InviteMemberRequest!) "
    f"{{ _invite_members(params: $data) {{ message Users {{ {USER_FRAGMENT} }} }} }}"
)
ADMIN_ADD_WEBHOOK = (
    "mutation adminAddWebhook($data: AddWebhookRequest!) "
    "{ _add_webhook(params: $data) { message } }"
)
ADMIN_UPDATE_WEBHOOK = (
    "mutation adminUpdateWebhook($data: UpdateWebhookRequest!) "
    "{ _update_webhook(params: $data) { message } }"
)
ADMIN_DELETE_WEBHOOK = (
    "mutation adminDeleteWebhook($data: WebhookRequest!) "
    "{ _delete_webhook(params: $data) { message } }"
)
ADMIN_GET_WEBHOOK = (
    "query adminWebhook($data: WebhookRequest!) "
    f"{{ _webhook(params: $data) {{ {WEBHOOK_FRAGMENT} }} }}"
)
ADMIN_WEBHOOKS = (
    "query adminWebhooks($data: PaginationRequest) "
    f"{{ _webhooks(params: $data) {{ {PAGINATION_FRAGMENT} webhooks {{ {WEBHOOK_FRAGMENT} }} }} }}"
)
ADMIN_WEBHOOK_LOGS = (
    "query adminWebhookLogs($data: ListWebhookLogRequest) "
    f"{{ _webhook_logs(params: $data) {{ {PAGINATION_FRAGMENT} "
    f"webhook_logs {{ {WEBHOOK_LOG_FRAGMENT} }} }} }}"
)
ADMIN_TEST_ENDPOINT = (
    "mutation adminTestEndpoint($data: TestEndpointRequest!) "
    "{ _test_endpoint(params: $data) { http_status response } }"
)
ADMIN_ADD_EMAIL_TEMPLATE = (
    "mutation adminAddEmailTemplate($data: AddEmailTemplateRequest!) "
    "{ _add_email_template(params: $data) { message } }"
)
ADMIN_UPDATE_EMAIL_TEMPLATE = (
    "mutation adminUpdateEmailTemplate($data: UpdateEmailTemplateRequest!) "
    "{ _update_email_template(params: $data) { message } }"
)
ADMIN_DELETE_EMAIL_TEMPLATE = (
    "mutation adminDeleteEmailTemplate($data: DeleteEmailTemplateRequest!) "
    "{ _delete_email_template(params: $data) { message } }"
)
ADMIN_EMAIL_TEMPLATES = (
    "query adminEmailTemplates($data: PaginationRequest) "
    f"{{ _email_templates(params: $data) {{ {PAGINATION_FRAGMENT} "
    f"email_templates {{ {EMAIL_TEMPLATE_FRAGMENT} }} }} }}"
)
ADMIN_AUDIT_LOGS = (
    "query adminAuditLogs($data: ListAuditLogRequest) "
    f"{{ _audit_logs(params: $data) {{ {PAGINATION_FRAGMENT} "
    f"audit_logs {{ {AUDIT_LOG_FRAGMENT} }} }} }}"
)
ADMIN_UPDATE_ENV = (
    "mutation adminUpdateEnv($data: UpdateEnvRequest!) "
    "{ _update_env(params: $data) { message } }"
)
ADMIN_GENERATE_JWT_KEYS = (
    "mutation adminGenerateJwtKeys($data: GenerateJWTKeysRequest!) "
    "{ _generate_jwt_keys(params: $data) { secret public_key private_key } }"
)
ADMIN_FGA_WRITE_MODEL = (
    "mutation adminFgaWriteModel($data: FgaWriteModelInput!) "
    "{ _fga_write_model(params: $data) { id dsl } }"
)
ADMIN_FGA_WRITE_TUPLES = (
    "mutation adminFgaWriteTuples($data: FgaWriteTuplesInput!) "
    "{ _fga_write_tuples(params: $data) { message } }"
)
ADMIN_FGA_DELETE_TUPLES = (
    "mutation adminFgaDeleteTuples($data: FgaWriteTuplesInput!) "
    "{ _fga_delete_tuples(params: $data) { message } }"
)
ADMIN_FGA_READ_TUPLES = (
    "query adminFgaReadTuples($data: FgaReadTuplesInput!) "
    "{ _fga_read_tuples(params: $data) "
    "{ tuples { user relation object } continuation_token } }"
)
ADMIN_FGA_LIST_USERS = (
    "query adminFgaListUsers($data: FgaListUsersInput!) "
    "{ _fga_list_users(params: $data) { users } }"
)
ADMIN_FGA_EXPAND = (
    "query adminFgaExpand($data: FgaExpandInput!) "
    "{ _fga_expand(params: $data) { tree } }"
)

# --------------------------------------------------------------------------- #
# Machine-agent-identity admin ops: clients (service accounts), trusted
# issuers, organizations, org SSO connections, SCIM endpoints.
# --------------------------------------------------------------------------- #
CLIENT_FRAGMENT = "id client_id name description allowed_scopes is_active created_at updated_at"
TRUSTED_ISSUER_FRAGMENT = (
    "id service_account_id name issuer_url key_source_type jwks_url expected_aud "
    "subject_claim allowed_subjects issuer_type is_active spiffe_refresh_hint_seconds "
    "created_at updated_at"
)
ORGANIZATION_FRAGMENT = "id name display_name enabled created_at updated_at"
ORG_MEMBER_FRAGMENT = "id org_id user_id roles created_at updated_at"
ORG_OIDC_CONNECTION_FRAGMENT = (
    "id org_id name issuer_url sso_client_id scopes redirect_uri is_active "
    "created_at updated_at"
)
ORG_SAML_CONNECTION_FRAGMENT = (
    "id org_id name idp_entity_id idp_sso_url sp_entity_id acs_url attribute_mapping "
    "allow_idp_initiated is_active created_at updated_at"
)
SCIM_ENDPOINT_FRAGMENT = "id org_id enabled created_at updated_at"

ADMIN_CREATE_CLIENT = (
    "mutation adminCreateClient($data: CreateClientRequest!) "
    f"{{ _create_client(params: $data) {{ client {{ {CLIENT_FRAGMENT} }} client_secret }} }}"
)
ADMIN_UPDATE_CLIENT = (
    "mutation adminUpdateClient($data: UpdateClientRequest!) "
    f"{{ _update_client(params: $data) {{ {CLIENT_FRAGMENT} }} }}"
)
ADMIN_DELETE_CLIENT = (
    "mutation adminDeleteClient($data: ClientRequest!) "
    "{ _delete_client(params: $data) { message } }"
)
ADMIN_ROTATE_CLIENT_SECRET = (
    "mutation adminRotateClientSecret($data: ClientRequest!) "
    f"{{ _rotate_client_secret(params: $data) "
    f"{{ client {{ {CLIENT_FRAGMENT} }} client_secret }} }}"
)
ADMIN_GET_CLIENT = (
    "query adminClient($data: ClientRequest!) "
    f"{{ _client(params: $data) {{ {CLIENT_FRAGMENT} }} }}"
)
ADMIN_CLIENTS = (
    "query adminClients($data: ListClientsRequest) "
    f"{{ _clients(params: $data) {{ {PAGINATION_FRAGMENT} clients {{ {CLIENT_FRAGMENT} }} }} }}"
)
ADMIN_ADD_TRUSTED_ISSUER = (
    "mutation adminAddTrustedIssuer($data: AddTrustedIssuerRequest!) "
    f"{{ _add_trusted_issuer(params: $data) {{ {TRUSTED_ISSUER_FRAGMENT} }} }}"
)
ADMIN_UPDATE_TRUSTED_ISSUER = (
    "mutation adminUpdateTrustedIssuer($data: UpdateTrustedIssuerRequest!) "
    f"{{ _update_trusted_issuer(params: $data) {{ {TRUSTED_ISSUER_FRAGMENT} }} }}"
)
ADMIN_DELETE_TRUSTED_ISSUER = (
    "mutation adminDeleteTrustedIssuer($data: TrustedIssuerRequest!) "
    "{ _delete_trusted_issuer(params: $data) { message } }"
)
ADMIN_GET_TRUSTED_ISSUER = (
    "query adminTrustedIssuer($data: TrustedIssuerRequest!) "
    f"{{ _trusted_issuer(params: $data) {{ {TRUSTED_ISSUER_FRAGMENT} }} }}"
)
ADMIN_TRUSTED_ISSUERS = (
    "query adminTrustedIssuers($data: ListTrustedIssuersRequest) "
    f"{{ _trusted_issuers(params: $data) {{ {PAGINATION_FRAGMENT} "
    f"trusted_issuers {{ {TRUSTED_ISSUER_FRAGMENT} }} }} }}"
)
ADMIN_CREATE_ORGANIZATION = (
    "mutation adminCreateOrganization($data: CreateOrganizationRequest!) "
    f"{{ _create_organization(params: $data) {{ {ORGANIZATION_FRAGMENT} }} }}"
)
ADMIN_UPDATE_ORGANIZATION = (
    "mutation adminUpdateOrganization($data: UpdateOrganizationRequest!) "
    f"{{ _update_organization(params: $data) {{ {ORGANIZATION_FRAGMENT} }} }}"
)
ADMIN_DELETE_ORGANIZATION = (
    "mutation adminDeleteOrganization($data: OrganizationRequest!) "
    "{ _delete_organization(params: $data) { message } }"
)
ADMIN_ADD_ORG_MEMBER = (
    "mutation adminAddOrgMember($data: AddOrgMemberRequest!) "
    f"{{ _add_org_member(params: $data) {{ {ORG_MEMBER_FRAGMENT} }} }}"
)
ADMIN_REMOVE_ORG_MEMBER = (
    "mutation adminRemoveOrgMember($data: RemoveOrgMemberRequest!) "
    "{ _remove_org_member(params: $data) { message } }"
)
ADMIN_GET_ORGANIZATION = (
    "query adminOrganization($data: OrganizationRequest!) "
    f"{{ _organization(params: $data) {{ {ORGANIZATION_FRAGMENT} }} }}"
)
ADMIN_ORGANIZATIONS = (
    "query adminOrganizations($data: ListOrganizationsRequest) "
    f"{{ _organizations(params: $data) {{ {PAGINATION_FRAGMENT} "
    f"organizations {{ {ORGANIZATION_FRAGMENT} }} }} }}"
)
ADMIN_ORG_MEMBERS = (
    "query adminOrgMembers($data: ListOrgMembersRequest!) "
    f"{{ _org_members(params: $data) {{ {PAGINATION_FRAGMENT} "
    f"org_members {{ {ORG_MEMBER_FRAGMENT} }} }} }}"
)
ADMIN_CREATE_ORG_OIDC_CONNECTION = (
    "mutation adminCreateOrgOIDCConnection($data: CreateOrgOIDCConnectionRequest!) "
    f"{{ _create_org_oidc_connection(params: $data) {{ {ORG_OIDC_CONNECTION_FRAGMENT} }} }}"
)
ADMIN_UPDATE_ORG_OIDC_CONNECTION = (
    "mutation adminUpdateOrgOIDCConnection($data: UpdateOrgOIDCConnectionRequest!) "
    f"{{ _update_org_oidc_connection(params: $data) {{ {ORG_OIDC_CONNECTION_FRAGMENT} }} }}"
)
ADMIN_DELETE_ORG_OIDC_CONNECTION = (
    "mutation adminDeleteOrgOIDCConnection($data: OrgOIDCConnectionRequest!) "
    "{ _delete_org_oidc_connection(params: $data) { message } }"
)
ADMIN_GET_ORG_OIDC_CONNECTION = (
    "query adminOrgOIDCConnection($data: OrgOIDCConnectionRequest!) "
    f"{{ _org_oidc_connection(params: $data) {{ {ORG_OIDC_CONNECTION_FRAGMENT} }} }}"
)
ADMIN_CREATE_ORG_SAML_CONNECTION = (
    "mutation adminCreateOrgSAMLConnection($data: CreateOrgSAMLConnectionRequest!) "
    f"{{ _create_org_saml_connection(params: $data) {{ {ORG_SAML_CONNECTION_FRAGMENT} }} }}"
)
ADMIN_UPDATE_ORG_SAML_CONNECTION = (
    "mutation adminUpdateOrgSAMLConnection($data: UpdateOrgSAMLConnectionRequest!) "
    f"{{ _update_org_saml_connection(params: $data) {{ {ORG_SAML_CONNECTION_FRAGMENT} }} }}"
)
ADMIN_DELETE_ORG_SAML_CONNECTION = (
    "mutation adminDeleteOrgSAMLConnection($data: OrgSAMLConnectionRequest!) "
    "{ _delete_org_saml_connection(params: $data) { message } }"
)
ADMIN_GET_ORG_SAML_CONNECTION = (
    "query adminOrgSAMLConnection($data: OrgSAMLConnectionRequest!) "
    f"{{ _org_saml_connection(params: $data) {{ {ORG_SAML_CONNECTION_FRAGMENT} }} }}"
)
ADMIN_CREATE_SCIM_ENDPOINT = (
    "mutation adminCreateScimEndpoint($data: CreateScimEndpointRequest!) "
    f"{{ _create_scim_endpoint(params: $data) "
    f"{{ scim_endpoint {{ {SCIM_ENDPOINT_FRAGMENT} }} token }} }}"
)
ADMIN_ROTATE_SCIM_TOKEN = (
    "mutation adminRotateScimToken($data: ScimEndpointRequest!) "
    f"{{ _rotate_scim_token(params: $data) "
    f"{{ scim_endpoint {{ {SCIM_ENDPOINT_FRAGMENT} }} token }} }}"
)
ADMIN_DELETE_SCIM_ENDPOINT = (
    "mutation adminDeleteScimEndpoint($data: ScimEndpointRequest!) "
    "{ _delete_scim_endpoint(params: $data) { message } }"
)
ADMIN_GET_SCIM_ENDPOINT = (
    "query adminScimEndpoint($data: ScimEndpointRequest!) "
    f"{{ _scim_endpoint(params: $data) {{ {SCIM_ENDPOINT_FRAGMENT} }} }}"
)

# --------------------------------------------------------------------------- #
# SAML IdP (Authorizer as Identity Provider for downstream SPs), user
# organizations, and org domains (home-realm discovery).
# --------------------------------------------------------------------------- #
SAML_SERVICE_PROVIDER_FRAGMENT = (
    "id org_id name entity_id acs_url sp_cert_pem name_id_format mapped_attributes "
    "allow_idp_initiated is_active created_at updated_at"
)
SAML_IDP_KEY_FRAGMENT = "id org_id cert_pem algorithm status created_at updated_at"
USER_ORGANIZATION_FRAGMENT = f"organization {{ {ORGANIZATION_FRAGMENT} }} roles"
ORG_DOMAIN_FRAGMENT = "domain org_id verified_at created_at updated_at"
ORG_DOMAIN_CHALLENGE_FRAGMENT = "domain record_type record_name record_value"

ADMIN_CREATE_SAML_SERVICE_PROVIDER = (
    "mutation adminCreateSamlServiceProvider($data: CreateSAMLServiceProviderRequest!) "
    f"{{ _create_saml_service_provider(params: $data) {{ {SAML_SERVICE_PROVIDER_FRAGMENT} }} }}"
)
ADMIN_UPDATE_SAML_SERVICE_PROVIDER = (
    "mutation adminUpdateSamlServiceProvider($data: UpdateSAMLServiceProviderRequest!) "
    f"{{ _update_saml_service_provider(params: $data) {{ {SAML_SERVICE_PROVIDER_FRAGMENT} }} }}"
)
ADMIN_DELETE_SAML_SERVICE_PROVIDER = (
    "mutation adminDeleteSamlServiceProvider($data: SAMLServiceProviderRequest!) "
    "{ _delete_saml_service_provider(params: $data) { message } }"
)
ADMIN_GET_SAML_SERVICE_PROVIDER = (
    "query adminSamlServiceProvider($data: SAMLServiceProviderRequest!) "
    f"{{ _saml_service_provider(params: $data) {{ {SAML_SERVICE_PROVIDER_FRAGMENT} }} }}"
)
ADMIN_LIST_SAML_SERVICE_PROVIDERS = (
    "query adminListSamlServiceProviders($data: ListSAMLServiceProvidersRequest!) "
    f"{{ _list_saml_service_providers(params: $data) {{ {PAGINATION_FRAGMENT} "
    f"saml_service_providers {{ {SAML_SERVICE_PROVIDER_FRAGMENT} }} }} }}"
)
ADMIN_ROTATE_SAML_IDP_CERT = (
    "mutation adminRotateSamlIdpCert($data: RotateSAMLIDPCertRequest!) "
    f"{{ _rotate_saml_idp_cert(params: $data) {{ {SAML_IDP_KEY_FRAGMENT} }} }}"
)
ADMIN_RETIRE_SAML_IDP_KEY = (
    "mutation adminRetireSamlIdpKey($data: RetireSAMLIDPKeyRequest!) "
    "{ _retire_saml_idp_key(params: $data) { message } }"
)
ADMIN_LIST_SAML_IDP_KEYS = (
    "query adminListSamlIdpKeys($data: ListSAMLIDPKeysRequest!) "
    f"{{ _list_saml_idp_keys(params: $data) {{ {SAML_IDP_KEY_FRAGMENT} }} }}"
)
ADMIN_IMPORT_SAML_SP_METADATA = (
    "mutation adminImportSamlSpMetadata($data: ImportSAMLSPMetadataRequest!) "
    "{ _import_saml_sp_metadata(params: $data) { entity_id acs_url certificate } }"
)

ADMIN_USER_ORGANIZATIONS = (
    "query adminUserOrganizations($data: UserOrganizationsRequest!) "
    f"{{ _user_organizations(params: $data) {{ {PAGINATION_FRAGMENT} "
    f"user_organizations {{ {USER_ORGANIZATION_FRAGMENT} }} }} }}"
)

ADMIN_REQUEST_ORG_DOMAIN = (
    "mutation adminRequestOrgDomain($data: RequestOrgDomainRequest!) "
    f"{{ _request_org_domain(params: $data) {{ {ORG_DOMAIN_CHALLENGE_FRAGMENT} }} }}"
)
ADMIN_VERIFY_ORG_DOMAIN = (
    "mutation adminVerifyOrgDomain($data: VerifyOrgDomainRequest!) "
    f"{{ _verify_org_domain(params: $data) {{ {ORG_DOMAIN_FRAGMENT} }} }}"
)
ADMIN_ADD_VERIFIED_ORG_DOMAIN = (
    "mutation adminAddVerifiedOrgDomain($data: AddVerifiedOrgDomainRequest!) "
    f"{{ _add_verified_org_domain(params: $data) {{ {ORG_DOMAIN_FRAGMENT} }} }}"
)
ADMIN_DELETE_ORG_DOMAIN = (
    "mutation adminDeleteOrgDomain($data: DeleteOrgDomainRequest!) "
    "{ _delete_org_domain(params: $data) { message } }"
)
ADMIN_ORG_DOMAINS = (
    "query adminOrgDomains($data: ListOrgDomainsRequest!) "
    f"{{ _org_domains(params: $data) {{ {PAGINATION_FRAGMENT} "
    f"org_domains {{ {ORG_DOMAIN_FRAGMENT} }} }} }}"
)
