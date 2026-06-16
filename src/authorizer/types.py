"""Request/response data models and enums for the Authorizer SDK."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any


# --------------------------------------------------------------------------- #
# Enums
# --------------------------------------------------------------------------- #
class TokenType(str, Enum):
    ACCESS_TOKEN = "access_token"
    ID_TOKEN = "id_token"
    REFRESH_TOKEN = "refresh_token"


class ResponseTypes(str, Enum):
    CODE = "code"
    TOKEN = "token"


class OAuthProviders(str, Enum):
    APPLE = "apple"
    GITHUB = "github"
    GOOGLE = "google"
    FACEBOOK = "facebook"
    LINKEDIN = "linkedin"
    TWITTER = "twitter"
    MICROSOFT = "microsoft"
    TWITCH = "twitch"
    ROBLOX = "roblox"
    DISCORD = "discord"


# --------------------------------------------------------------------------- #
# Serialization helpers
# --------------------------------------------------------------------------- #
def _to_payload(value: Any) -> Any:
    """Recursively convert dataclasses/enums/containers to JSON-ready data, dropping None."""
    if isinstance(value, Enum):
        return value.value
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        out: dict[str, Any] = {}
        for f in fields(value):
            v = getattr(value, f.name)
            if v is None:
                continue
            out[f.name] = _to_payload(v)
        return out
    if isinstance(value, list):
        return [_to_payload(v) for v in value if v is not None]
    if isinstance(value, dict):
        return {k: _to_payload(v) for k, v in value.items() if v is not None}
    return value


class _Request:
    """Mixin giving request dataclasses a JSON-ready ``to_dict``."""

    def to_dict(self) -> dict[str, Any]:
        return _to_payload(self)  # type: ignore[no-any-return]


def _known(cls: Any, data: dict[str, Any]) -> dict[str, Any]:
    """Return only the keys of ``data`` that are fields of ``cls`` (drops unknowns)."""
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in data.items() if k in names}


# --------------------------------------------------------------------------- #
# Request types
# --------------------------------------------------------------------------- #
@dataclass
class LoginRequest(_Request):
    password: str
    email: str | None = None
    phone_number: str | None = None
    roles: list[str] | None = None
    scope: list[str] | None = None
    state: str | None = None


@dataclass
class SignUpRequest(_Request):
    password: str
    confirm_password: str
    email: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    middle_name: str | None = None
    nickname: str | None = None
    picture: str | None = None
    gender: str | None = None
    birthdate: str | None = None
    phone_number: str | None = None
    roles: list[str] | None = None
    scope: list[str] | None = None
    redirect_uri: str | None = None
    is_multi_factor_auth_enabled: bool | None = None
    app_data: dict[str, Any] | None = None
    state: str | None = None


@dataclass
class MagicLinkLoginRequest(_Request):
    email: str
    roles: list[str] | None = None
    scope: list[str] | None = None
    state: str | None = None
    redirect_uri: str | None = None


@dataclass
class VerifyOTPRequest(_Request):
    otp: str
    email: str | None = None
    phone_number: str | None = None
    is_totp: bool | None = None
    state: str | None = None


@dataclass
class VerifyEmailRequest(_Request):
    token: str
    state: str | None = None


@dataclass
class ResendOTPRequest(_Request):
    email: str | None = None
    phone_number: str | None = None
    state: str | None = None


@dataclass
class ResendVerifyEmailRequest(_Request):
    email: str
    identifier: str | None = None


@dataclass
class ForgotPasswordRequest(_Request):
    email: str | None = None
    phone_number: str | None = None
    state: str | None = None
    redirect_uri: str | None = None


@dataclass
class ResetPasswordRequest(_Request):
    password: str
    confirm_password: str
    token: str | None = None
    otp: str | None = None
    phone_number: str | None = None


@dataclass
class ValidateJWTTokenRequest(_Request):
    token: str
    token_type: TokenType
    roles: list[str] | None = None


@dataclass
class ValidateSessionRequest(_Request):
    cookie: str | None = None
    roles: list[str] | None = None


@dataclass
class SessionQueryRequest(_Request):
    roles: list[str] | None = None
    scope: list[str] | None = None


@dataclass
class UpdateProfileRequest(_Request):
    email: str | None = None
    new_password: str | None = None
    confirm_new_password: str | None = None
    old_password: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    middle_name: str | None = None
    nickname: str | None = None
    picture: str | None = None
    gender: str | None = None
    birthdate: str | None = None
    phone_number: str | None = None
    roles: list[str] | None = None
    scope: list[str] | None = None
    redirect_uri: str | None = None
    is_multi_factor_auth_enabled: bool | None = None
    app_data: dict[str, Any] | None = None


@dataclass
class GetTokenRequest(_Request):
    code: str | None = None
    grant_type: str | None = None
    refresh_token: str | None = None
    code_verifier: str | None = None


@dataclass
class RevokeTokenRequest(_Request):
    refresh_token: str


# NOTE: `object` shadows the Python builtin intentionally to match the Authorizer API field name.
@dataclass
class FgaTupleInput(_Request):
    user: str
    relation: str
    object: str


@dataclass
class PermissionCheckInput(_Request):
    relation: str
    object: str
    contextual_tuples: list[FgaTupleInput] | None = None


@dataclass
class CheckPermissionsRequest(_Request):
    checks: list[PermissionCheckInput]
    user: str | None = None


@dataclass
class ListPermissionsRequest(_Request):
    relation: str | None = None
    object_type: str | None = None
    user: str | None = None


# --------------------------------------------------------------------------- #
# Response types
# --------------------------------------------------------------------------- #
@dataclass
class User:
    id: str = ""
    email: str | None = None
    email_verified: bool | None = None
    given_name: str | None = None
    family_name: str | None = None
    middle_name: str | None = None
    nickname: str | None = None
    preferred_username: str | None = None
    picture: str | None = None
    signup_methods: str | None = None
    gender: str | None = None
    birthdate: str | None = None
    phone_number: str | None = None
    phone_number_verified: bool | None = None
    roles: list[str] | None = None
    created_at: int | None = None
    updated_at: int | None = None
    is_multi_factor_auth_enabled: bool | None = None
    app_data: dict[str, Any] | None = None
    revoked_timestamp: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> User:
        return cls(**_known(cls, data))


@dataclass
class AuthToken:
    message: str | None = None
    access_token: str | None = None
    expires_in: int | None = None
    id_token: str | None = None
    refresh_token: str | None = None
    should_show_email_otp_screen: bool | None = None
    should_show_mobile_otp_screen: bool | None = None
    should_show_totp_screen: bool | None = None
    authenticator_scanner_image: str | None = None
    authenticator_secret: str | None = None
    authenticator_recovery_codes: list[str] | None = None
    user: User | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthToken:
        kwargs = _known(cls, data)
        if isinstance(kwargs.get("user"), dict):
            kwargs["user"] = User.from_dict(kwargs["user"])
        return cls(**kwargs)


@dataclass
class GenericResponse:
    message: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GenericResponse:
        return cls(**_known(cls, data))


@dataclass
class ForgotPasswordResponse:
    message: str = ""
    should_show_mobile_otp_screen: bool | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ForgotPasswordResponse:
        return cls(**_known(cls, data))


@dataclass
class ValidateJWTTokenResponse:
    is_valid: bool = False
    claims: dict[str, Any] | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidateJWTTokenResponse:
        claims = data.get("claims")
        return cls(
            is_valid=bool(data.get("is_valid", False)),
            claims=claims if isinstance(claims, dict) else None,
        )


@dataclass
class ValidateSessionResponse:
    is_valid: bool = False
    user: User | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ValidateSessionResponse:
        is_valid = bool(data.get("is_valid", False))
        user_data = data.get("user")
        user = User.from_dict(user_data) if isinstance(user_data, dict) else None
        return cls(is_valid=is_valid, user=user)


@dataclass
class MetaData:
    version: str = ""
    client_id: str = ""
    is_google_login_enabled: bool = False
    is_facebook_login_enabled: bool = False
    is_github_login_enabled: bool = False
    is_linkedin_login_enabled: bool = False
    is_apple_login_enabled: bool = False
    is_twitter_login_enabled: bool = False
    is_discord_login_enabled: bool = False
    is_microsoft_login_enabled: bool = False
    is_twitch_login_enabled: bool = False
    is_roblox_login_enabled: bool = False
    is_email_verification_enabled: bool = False
    is_basic_authentication_enabled: bool = False
    is_magic_link_login_enabled: bool = False
    is_sign_up_enabled: bool = False
    is_strong_password_enabled: bool = False
    is_multi_factor_auth_enabled: bool = False
    is_mobile_basic_authentication_enabled: bool = False
    is_phone_verification_enabled: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> MetaData:
        return cls(**_known(cls, data))


@dataclass
class GetTokenResponse:
    access_token: str = ""
    expires_in: int = 0
    id_token: str = ""
    refresh_token: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GetTokenResponse:
        return cls(**_known(cls, data))


@dataclass
class PermissionCheckResult:
    relation: str = ""
    object: str = ""
    allowed: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PermissionCheckResult:
        return cls(**_known(cls, data))


@dataclass
class CheckPermissionsResponse:
    results: list[PermissionCheckResult] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CheckPermissionsResponse:
        raw = data.get("results")
        items = raw if isinstance(raw, list) else []
        results = [PermissionCheckResult.from_dict(r) for r in items if isinstance(r, dict)]
        return cls(results=results)


@dataclass
class Permission:
    object: str = ""
    relation: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Permission:
        return cls(**_known(cls, data))


@dataclass
class ListPermissionsResponse:
    objects: list[str] = field(default_factory=list)
    permissions: list[Permission] = field(default_factory=list)
    truncated: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ListPermissionsResponse:
        raw_objects = data.get("objects")
        raw_perms = data.get("permissions")
        perms = raw_perms if isinstance(raw_perms, list) else []
        return cls(
            objects=list(raw_objects) if isinstance(raw_objects, list) else [],
            permissions=[Permission.from_dict(p) for p in perms if isinstance(p, dict)],
            truncated=bool(data.get("truncated", False)),
        )


# --------------------------------------------------------------------------- #
# Admin request types
# --------------------------------------------------------------------------- #
@dataclass
class PaginationRequest(_Request):
    page: int | None = None
    limit: int | None = None
    page_token: str | None = None


@dataclass
class PaginatedRequest(_Request):
    pagination: PaginationRequest | None = None


@dataclass
class AdminLoginRequest(_Request):
    admin_secret: str


@dataclass
class GetUserRequest(_Request):
    id: str | None = None
    email: str | None = None


@dataclass
class UpdateUserRequest(_Request):
    id: str
    email: str | None = None
    email_verified: bool | None = None
    given_name: str | None = None
    family_name: str | None = None
    middle_name: str | None = None
    nickname: str | None = None
    gender: str | None = None
    birthdate: str | None = None
    phone_number: str | None = None
    phone_number_verified: bool | None = None
    picture: str | None = None
    roles: list[str] | None = None
    is_multi_factor_auth_enabled: bool | None = None
    app_data: dict[str, Any] | None = None


@dataclass
class DeleteUserRequest(_Request):
    email: str


@dataclass
class UpdateAccessRequest(_Request):
    user_id: str


@dataclass
class InviteMembersRequest(_Request):
    emails: list[str]
    redirect_uri: str | None = None


@dataclass
class AddWebhookRequest(_Request):
    event_name: str
    endpoint: str
    enabled: bool = True
    event_description: str | None = None
    headers: dict[str, Any] | None = None


@dataclass
class UpdateWebhookRequest(_Request):
    id: str
    event_name: str | None = None
    event_description: str | None = None
    endpoint: str | None = None
    enabled: bool | None = None
    headers: dict[str, Any] | None = None


@dataclass
class WebhookRequest(_Request):
    id: str


@dataclass
class ListWebhookLogRequest(_Request):
    pagination: PaginationRequest | None = None
    webhook_id: str | None = None


@dataclass
class TestEndpointRequest(_Request):
    endpoint: str
    event_name: str
    event_description: str | None = None
    headers: dict[str, Any] | None = None


@dataclass
class AddEmailTemplateRequest(_Request):
    event_name: str
    subject: str
    template: str
    design: str | None = None


@dataclass
class UpdateEmailTemplateRequest(_Request):
    id: str
    event_name: str | None = None
    template: str | None = None
    subject: str | None = None
    design: str | None = None


@dataclass
class DeleteEmailTemplateRequest(_Request):
    id: str


@dataclass
class ListAuditLogRequest(_Request):
    pagination: PaginationRequest | None = None
    action: str | None = None
    actor_id: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    from_timestamp: int | None = None
    to_timestamp: int | None = None


@dataclass
class AdminSignupRequest(_Request):
    admin_secret: str


@dataclass
class GenerateJWTKeysRequest(_Request):
    type: str


@dataclass
class FgaWriteModelRequest(_Request):
    dsl: str


@dataclass
class FgaWriteTuplesRequest(_Request):
    tuples: list[FgaTupleInput]


@dataclass
class FgaReadTuplesRequest(_Request):
    user: str | None = None
    relation: str | None = None
    object: str | None = None
    page_size: int | None = None
    continuation_token: str | None = None


@dataclass
class FgaListUsersRequest(_Request):
    object: str
    relation: str
    user_type: str


@dataclass
class FgaExpandRequest(_Request):
    relation: str
    object: str


# --------------------------------------------------------------------------- #
# Admin response types
# --------------------------------------------------------------------------- #
@dataclass
class Pagination:
    limit: int = 0
    page: int = 0
    offset: int = 0
    total: int = 0
    next_page_token: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Pagination:
        return cls(**_known(cls, data))


def _pagination(data: dict[str, Any]) -> Pagination:
    raw = data.get("pagination")
    return Pagination.from_dict(raw) if isinstance(raw, dict) else Pagination()


def _users(data: dict[str, Any], key: str) -> list[User]:
    raw = data.get(key)
    items = raw if isinstance(raw, list) else []
    return [User.from_dict(u) for u in items if isinstance(u, dict)]


@dataclass
class AdminMeta:
    roles: list[str] = field(default_factory=list)
    default_roles: list[str] = field(default_factory=list)
    protected_roles: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdminMeta:
        return cls(**_known(cls, data))


@dataclass
class UsersResponse:
    users: list[User] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UsersResponse:
        return cls(users=_users(data, "users"), pagination=_pagination(data))


@dataclass
class VerificationRequest:
    id: str = ""
    identifier: str | None = None
    token: str | None = None
    email: str | None = None
    expires: int | None = None
    created_at: int | None = None
    updated_at: int | None = None
    nonce: str | None = None
    redirect_uri: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationRequest:
        return cls(**_known(cls, data))


@dataclass
class VerificationRequestsResponse:
    verification_requests: list[VerificationRequest] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VerificationRequestsResponse:
        raw = data.get("verification_requests")
        items = raw if isinstance(raw, list) else []
        return cls(
            verification_requests=[
                VerificationRequest.from_dict(v) for v in items if isinstance(v, dict)
            ],
            pagination=_pagination(data),
        )


@dataclass
class InviteMembersResponse:
    message: str = ""
    users: list[User] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InviteMembersResponse:
        # GraphQL returns `Users` (capitalized); REST/grpc return `users`.
        key = "Users" if "Users" in data else "users"
        return cls(message=str(data.get("message", "")), users=_users(data, key))


@dataclass
class Webhook:
    id: str = ""
    event_name: str | None = None
    event_description: str | None = None
    endpoint: str | None = None
    enabled: bool | None = None
    headers: dict[str, Any] | None = None
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Webhook:
        return cls(**_known(cls, data))


@dataclass
class WebhooksResponse:
    webhooks: list[Webhook] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WebhooksResponse:
        raw = data.get("webhooks")
        items = raw if isinstance(raw, list) else []
        return cls(
            webhooks=[Webhook.from_dict(w) for w in items if isinstance(w, dict)],
            pagination=_pagination(data),
        )


@dataclass
class WebhookLog:
    id: str = ""
    http_status: int | None = None
    response: str | None = None
    request: str | None = None
    webhook_id: str | None = None
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WebhookLog:
        return cls(**_known(cls, data))


@dataclass
class WebhookLogsResponse:
    webhook_logs: list[WebhookLog] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WebhookLogsResponse:
        raw = data.get("webhook_logs")
        items = raw if isinstance(raw, list) else []
        return cls(
            webhook_logs=[WebhookLog.from_dict(w) for w in items if isinstance(w, dict)],
            pagination=_pagination(data),
        )


@dataclass
class TestEndpointResponse:
    http_status: int | None = None
    response: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TestEndpointResponse:
        return cls(**_known(cls, data))


@dataclass
class EmailTemplate:
    id: str = ""
    event_name: str | None = None
    template: str | None = None
    design: str | None = None
    subject: str | None = None
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EmailTemplate:
        return cls(**_known(cls, data))


@dataclass
class EmailTemplatesResponse:
    email_templates: list[EmailTemplate] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EmailTemplatesResponse:
        raw = data.get("email_templates")
        items = raw if isinstance(raw, list) else []
        return cls(
            email_templates=[EmailTemplate.from_dict(e) for e in items if isinstance(e, dict)],
            pagination=_pagination(data),
        )


@dataclass
class AuditLog:
    id: str = ""
    actor_id: str | None = None
    actor_type: str | None = None
    actor_email: str | None = None
    action: str | None = None
    resource_type: str | None = None
    resource_id: str | None = None
    ip_address: str | None = None
    user_agent: str | None = None
    metadata: str | None = None
    created_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditLog:
        return cls(**_known(cls, data))


@dataclass
class AuditLogsResponse:
    audit_logs: list[AuditLog] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuditLogsResponse:
        raw = data.get("audit_logs")
        items = raw if isinstance(raw, list) else []
        return cls(
            audit_logs=[AuditLog.from_dict(a) for a in items if isinstance(a, dict)],
            pagination=_pagination(data),
        )


@dataclass
class GenerateJWTKeysResponse:
    secret: str | None = None
    public_key: str | None = None
    private_key: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GenerateJWTKeysResponse:
        return cls(**_known(cls, data))


@dataclass
class FgaModel:
    id: str = ""
    dsl: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FgaModel:
        return cls(**_known(cls, data))


@dataclass
class FgaTuple:
    user: str = ""
    relation: str = ""
    object: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FgaTuple:
        return cls(**_known(cls, data))


@dataclass
class FgaReadTuplesResponse:
    tuples: list[FgaTuple] = field(default_factory=list)
    continuation_token: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FgaReadTuplesResponse:
        raw = data.get("tuples")
        items = raw if isinstance(raw, list) else []
        return cls(
            tuples=[FgaTuple.from_dict(x) for x in items if isinstance(x, dict)],
            continuation_token=data.get("continuation_token"),
        )


@dataclass
class FgaListUsersResponse:
    users: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FgaListUsersResponse:
        raw = data.get("users")
        return cls(users=list(raw) if isinstance(raw, list) else [])


@dataclass
class FgaExpandResponse:
    tree: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FgaExpandResponse:
        return cls(tree=str(data.get("tree", "")))
