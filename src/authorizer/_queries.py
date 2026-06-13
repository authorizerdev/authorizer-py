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
