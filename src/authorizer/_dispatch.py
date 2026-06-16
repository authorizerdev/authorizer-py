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
        ("rest", "grpc"), None, None, "POST", "/v1/admin/logout", None,
        "AdminLogout", "AdminLogoutRequest", None,
    ),
    "admin_session": MethodSpec(
        ("rest", "grpc"), None, None, "GET", "/v1/admin/session", None,
        "AdminSession", "AdminSessionRequest", None,
    ),
    "admin_meta": MethodSpec(
        ("rest", "grpc"), None, None, "GET", "/v1/admin/meta", "admin_meta",
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
        ("rest", "grpc"), None, None, "GET", "/v1/admin/fga/model", "model",
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
        ("rest", "grpc"), None, None, "POST", "/v1/admin/fga/reset", None,
        "FgaReset", "FgaResetRequest", None,
    ),
    # gql-only extras (no proto / no rest / no grpc).
    "admin_signup": MethodSpec(GQL_ONLY, q.ADMIN_SIGNUP, "_admin_signup"),
    "update_env": MethodSpec(GQL_ONLY, q.ADMIN_UPDATE_ENV, "_update_env"),
    "generate_jwt_keys": MethodSpec(GQL_ONLY, q.ADMIN_GENERATE_JWT_KEYS, "_generate_jwt_keys"),
}
