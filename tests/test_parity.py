"""Cross-client parity: both clients must expose the same 22-method surface."""

from __future__ import annotations

from authorizer.async_client import AsyncAuthorizerClient
from authorizer.client import AuthorizerClient

PUBLIC_METHODS = [
    "login",
    "signup",
    "magic_link_login",
    "verify_otp",
    "verify_email",
    "resend_otp",
    "resend_verify_email",
    "forgot_password",
    "reset_password",
    "validate_jwt_token",
    "validate_session",
    "get_meta_data",
    "get_session",
    "get_profile",
    "update_profile",
    "logout",
    "deactivate_account",
    "check_permissions",
    "list_permissions",
    "get_token",
    "revoke_token",
    "graphql_query",
    "skip_mfa_setup",
    "lock_mfa",
    "email_otp_mfa_setup",
    "sms_otp_mfa_setup",
    "totp_mfa_setup",
    "webauthn_registration_options",
    "webauthn_registration_verify",
    "webauthn_login_options",
    "webauthn_login_verify",
    "webauthn_delete_credential",
    "webauthn_credentials",
]


def test_both_clients_expose_the_same_method_surface() -> None:
    for name in PUBLIC_METHODS:
        assert hasattr(AuthorizerClient, name), f"sync missing {name}"
        assert hasattr(AsyncAuthorizerClient, name), f"async missing {name}"
