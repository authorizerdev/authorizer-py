"""GraphQL fragments and query/mutation strings used by the SDK.

Mirrors the queries in authorizer-go so server behavior is identical.
"""

from __future__ import annotations

USER_FRAGMENT = (
    "id email email_verified given_name family_name middle_name nickname "
    "preferred_username picture signup_methods gender birthdate phone_number "
    "phone_number_verified roles created_at updated_at is_multi_factor_auth_enabled "
    "app_data revoked_timestamp"
)

AUTH_TOKEN_FRAGMENT = (
    "message access_token expires_in refresh_token id_token "
    "should_show_email_otp_screen should_show_mobile_otp_screen should_show_totp_screen "
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
    "query adminUsers($data: PaginatedRequest) "
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
    "query adminVerificationRequests($data: PaginatedRequest) "
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
    "query adminWebhooks($data: PaginatedRequest) "
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
    "query adminEmailTemplates($data: PaginatedRequest) "
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
