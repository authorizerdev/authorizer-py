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
        return [_to_payload(v) for v in value]
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
        return cls(**_known(cls, data))


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
        results = [PermissionCheckResult.from_dict(r) for r in data.get("results") or []]
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
        return cls(
            objects=list(data.get("objects") or []),
            permissions=[Permission.from_dict(p) for p in data.get("permissions") or []],
            truncated=bool(data.get("truncated", False)),
        )
