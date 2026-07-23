"""Request/response data models and enums for the Authorizer SDK."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field, fields
from enum import Enum
from typing import Any

# --------------------------------------------------------------------------- #
# OAuth2 grant-type identifiers accepted by /oauth/token.
# client_credentials (RFC 6749 §4.4) and token-exchange (RFC 8693) are
# machine/service flows — server-side only.
# --------------------------------------------------------------------------- #
GRANT_TYPE_AUTHORIZATION_CODE = "authorization_code"
GRANT_TYPE_REFRESH_TOKEN = "refresh_token"
GRANT_TYPE_CLIENT_CREDENTIALS = "client_credentials"
GRANT_TYPE_TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"

# RFC 8693 token-type URNs for subject_token_type / actor_token_type.
TOKEN_TYPE_ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
TOKEN_TYPE_JWT = "urn:ietf:params:oauth:token-type:jwt"

# RFC 7523 JWT-bearer client_assertion_type (secretless client auth).
CLIENT_ASSERTION_TYPE_JWT_BEARER = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


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
    # -- client_credentials (RFC 6749 §4.4) — SERVER-SIDE ONLY -------------- #
    # client_secret authenticates the service account. Never expose it to
    # untrusted code.
    client_secret: str | None = None
    # scope is the space-delimited OAuth2 scope parameter (RFC 6749 §3.3);
    # omitted = the service account's full allowed scope set.
    scope: str | None = None
    # client_assertion / client_assertion_type carry the RFC 7523 JWT-bearer
    # client credential — the secretless workload-identity path (K8s SA
    # tokens, SPIFFE JWT-SVIDs, cloud OIDC tokens).
    client_assertion: str | None = None
    client_assertion_type: str | None = None
    # -- RFC 8693 token exchange (delegation) — SERVER-SIDE ONLY ------------ #
    # subject_token carries the authority being exercised (the user's token);
    # actor_token carries the acting agent's token. See the TOKEN_TYPE_*
    # constants for the *_token_type URNs.
    subject_token: str | None = None
    subject_token_type: str | None = None
    actor_token: str | None = None
    actor_token_type: str | None = None
    # resource is the RFC 8707 resource indicator the issued token is
    # audience-bound to (exactly one is required for token exchange).
    resource: str | None = None


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


# -- MFA setup / recovery ----------------------------------------------------- #
@dataclass
class SkipMfaSetupRequest(_Request):
    # Either email or phone_number is required, to resolve which user's MFA
    # session cookie this is.
    email: str | None = None
    phone_number: str | None = None
    state: str | None = None


@dataclass
class LockMfaRequest(_Request):
    # Either email or phone_number is required, to resolve which user's MFA
    # session cookie this is — same pattern as SkipMfaSetupRequest.
    email: str | None = None
    phone_number: str | None = None


@dataclass
class OtpMfaSetupRequest(_Request):
    """Shared request shape for email_otp_mfa_setup / sms_otp_mfa_setup / totp_mfa_setup.

    email/phone_number are only used in the MFA-session-cookie mode (no bearer
    token yet); ignored when the caller has a valid bearer token/session.
    """

    email: str | None = None
    phone_number: str | None = None


# -- WebAuthn / passkeys ------------------------------------------------------- #
@dataclass
class WebauthnRegistrationOptionsRequest(_Request):
    email: str | None = None
    phone_number: str | None = None


@dataclass
class WebauthnRegistrationVerifyRequest(_Request):
    # JSON-encoded PublicKeyCredential attestation response from
    # navigator.credentials.create().
    credential: str
    # Optional human label for the passkey (e.g. "MacBook Touch ID").
    name: str | None = None
    # Only used on the MFA-session-cookie path; ignored for a bearer-token caller.
    email: str | None = None
    phone_number: str | None = None
    state: str | None = None


@dataclass
class WebauthnLoginOptionsRequest(_Request):
    email: str | None = None


@dataclass
class WebauthnLoginVerifyRequest(_Request):
    # JSON-encoded PublicKeyCredential assertion response from
    # navigator.credentials.get().
    credential: str
    # OAuth authorize state to continue an in-progress authorization, if any.
    state: str | None = None


@dataclass
class WebauthnDeleteCredentialRequest(_Request):
    id: str


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
    # has_skipped_mfa_setup_at is set once the user explicitly skips the
    # optional MFA setup prompt shown at login. None means never skipped.
    has_skipped_mfa_setup_at: int | None = None
    # mfa_locked_at is set once the user reports losing access to their only
    # MFA factor(s) with no OTP fallback enrolled. None means not locked.
    mfa_locked_at: int | None = None
    # enrolled_mfa_methods lists verified MFA factors: any of "totp",
    # "webauthn", "email_otp", "sms_otp". Empty list means nothing enrolled.
    enrolled_mfa_methods: list[str] | None = None

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
    # should_offer_webauthn_mfa_verify is true when a passkey-verify offer is
    # available (see AuthResponse.should_offer_webauthn_mfa_verify in the
    # server schema for the exact semantics).
    should_offer_webauthn_mfa_verify: bool | None = None
    # should_offer_webauthn_mfa_setup / should_offer_email_otp_mfa_setup /
    # should_offer_sms_otp_mfa_setup are true, alongside should_show_totp_screen,
    # during a first-time optional-MFA offer for that factor.
    should_offer_webauthn_mfa_setup: bool | None = None
    should_offer_email_otp_mfa_setup: bool | None = None
    should_offer_sms_otp_mfa_setup: bool | None = None
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
    # id_token is only issued on user grants (authorization_code /
    # refresh_token) — absent for client_credentials and token exchange.
    id_token: str = ""
    refresh_token: str | None = None
    token_type: str | None = None
    # scope / issued_token_type are returned by the client_credentials and
    # token-exchange grants (RFC 6749 §5.1 / RFC 8693 §2.2).
    scope: str | None = None
    issued_token_type: str | None = None

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


@dataclass
class WebauthnRegistrationOptionsResponse:
    # JSON-encoded PublicKeyCredentialCreationOptions to pass to
    # navigator.credentials.create().
    options: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WebauthnRegistrationOptionsResponse:
        return cls(**_known(cls, data))


@dataclass
class WebauthnLoginOptionsResponse:
    # JSON-encoded PublicKeyCredentialRequestOptions to pass to
    # navigator.credentials.get().
    options: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WebauthnLoginOptionsResponse:
        return cls(**_known(cls, data))


@dataclass
class WebauthnCredentialInfo:
    id: str = ""
    name: str = ""
    transports: list[str] | None = None
    created_at: int | None = None
    updated_at: int | None = None
    last_used_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> WebauthnCredentialInfo:
        return cls(**_known(cls, data))


# --------------------------------------------------------------------------- #
# Admin request types
# --------------------------------------------------------------------------- #
@dataclass
class PaginationRequest(_Request):
    page: int | None = None
    limit: int | None = None
    page_token: str | None = None


@dataclass
class ListUsersRequest(_Request):
    """Request for :meth:`AuthorizerAdminClient.users`.

    ``query`` is an optional case-insensitive substring filter matched
    against email, given_name, family_name and nickname. Empty/absent
    means no filter (full list).
    """

    pagination: PaginationRequest | None = None
    query: str | None = None


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
    # reset_mfa, when true, clears the user's entire MFA state: mfa_locked_at,
    # is_multi_factor_auth_enabled, has_skipped_mfa_setup_at, and deletes all
    # enrolled authenticators/passkeys. The user's next login lands back on
    # the first-time setup screen, same as a brand-new account.
    reset_mfa: bool | None = None
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


# -- clients (service accounts / machine identities) ------------------------ #
@dataclass
class CreateClientRequest(_Request):
    name: str
    # allowed_scopes must contain at least one non-empty scope.
    allowed_scopes: list[str]
    description: str | None = None


@dataclass
class UpdateClientRequest(_Request):
    id: str
    name: str | None = None
    description: str | None = None
    allowed_scopes: list[str] | None = None
    is_active: bool | None = None


@dataclass
class ClientRequest(_Request):
    id: str


@dataclass
class ListClientsRequest(_Request):
    pagination: PaginationRequest | None = None


# -- trusted issuers --------------------------------------------------------- #
@dataclass
class AddTrustedIssuerRequest(_Request):
    service_account_id: str
    name: str
    issuer_url: str
    # key_source_type: "oidc_discovery" | "static_jwks_url" | "spiffe_bundle_endpoint"
    key_source_type: str
    expected_aud: str
    # issuer_type: "kubernetes_sa" | "spiffe_jwt" | "oidc" | "cloud_oidc"
    issuer_type: str
    jwks_url: str | None = None
    # subject_claim defaults to "sub" if omitted.
    subject_claim: str | None = None
    # allowed_subjects: comma-separated exact subject allow-list. Empty = deny-all.
    allowed_subjects: str | None = None
    spiffe_refresh_hint_seconds: int | None = None


@dataclass
class UpdateTrustedIssuerRequest(_Request):
    id: str
    name: str | None = None
    jwks_url: str | None = None
    expected_aud: str | None = None
    allowed_subjects: str | None = None
    is_active: bool | None = None
    spiffe_refresh_hint_seconds: int | None = None


@dataclass
class TrustedIssuerRequest(_Request):
    id: str


@dataclass
class ListTrustedIssuersRequest(_Request):
    service_account_id: str | None = None
    pagination: PaginationRequest | None = None


# -- organizations ------------------------------------------------------------ #
@dataclass
class CreateOrganizationRequest(_Request):
    # name must be a unique, URL-safe slug.
    name: str
    display_name: str | None = None


@dataclass
class UpdateOrganizationRequest(_Request):
    id: str
    name: str | None = None
    display_name: str | None = None
    enabled: bool | None = None


@dataclass
class OrganizationRequest(_Request):
    id: str


@dataclass
class ListOrganizationsRequest(_Request):
    pagination: PaginationRequest | None = None


@dataclass
class AddOrgMemberRequest(_Request):
    org_id: str
    user_id: str
    # roles defaults to an empty set when omitted.
    roles: list[str] | None = None


@dataclass
class RemoveOrgMemberRequest(_Request):
    org_id: str
    user_id: str


@dataclass
class ListOrgMembersRequest(_Request):
    org_id: str
    pagination: PaginationRequest | None = None


# -- org SSO connections ------------------------------------------------------ #
@dataclass
class CreateOrgOIDCConnectionRequest(_Request):
    org_id: str
    name: str
    # issuer_url: the upstream IdP issuer (its OIDC discovery base).
    issuer_url: str
    # client_id / client_secret: the credentials Authorizer holds AT the
    # upstream IdP. The secret is stored encrypted and never returned.
    client_id: str
    client_secret: str
    # scopes: space-separated. Defaults to "openid profile email" when omitted.
    scopes: str | None = None
    redirect_uri: str | None = None


@dataclass
class UpdateOrgOIDCConnectionRequest(_Request):
    id: str
    name: str | None = None
    issuer_url: str | None = None
    client_id: str | None = None
    # Supplying client_secret rotates it; omitting leaves the stored secret intact.
    client_secret: str | None = None
    scopes: str | None = None
    redirect_uri: str | None = None
    is_active: bool | None = None


@dataclass
class OrgOIDCConnectionRequest(_Request):
    # Look up by connection id OR by org_id (supply exactly one).
    id: str | None = None
    org_id: str | None = None


@dataclass
class CreateOrgSAMLConnectionRequest(_Request):
    org_id: str
    name: str
    # idp_entity_id: the upstream IdP entity ID (the assertion Issuer).
    idp_entity_id: str
    # idp_sso_url: the IdP Single Sign-On endpoint (HTTP-Redirect binding).
    idp_sso_url: str
    # idp_certificate: the IdP X.509 signing certificate (PEM).
    idp_certificate: str
    # sp_entity_id / acs_url: override the host-derived SP identity.
    sp_entity_id: str | None = None
    acs_url: str | None = None
    # attribute_mapping: JSON, e.g. {"email":"email","given_name":"firstName"}.
    attribute_mapping: str | None = None
    # allow_idp_initiated: default false (SP-initiated only).
    allow_idp_initiated: bool | None = None


@dataclass
class UpdateOrgSAMLConnectionRequest(_Request):
    id: str
    name: str | None = None
    idp_entity_id: str | None = None
    idp_sso_url: str | None = None
    # Supplying idp_certificate replaces it; omitting leaves the stored cert intact.
    idp_certificate: str | None = None
    sp_entity_id: str | None = None
    acs_url: str | None = None
    attribute_mapping: str | None = None
    allow_idp_initiated: bool | None = None
    is_active: bool | None = None


@dataclass
class OrgSAMLConnectionRequest(_Request):
    # Look up by connection id OR by org_id (supply exactly one).
    id: str | None = None
    org_id: str | None = None


# -- SCIM endpoints (one per org, keyed by org_id) ---------------------------- #
@dataclass
class CreateScimEndpointRequest(_Request):
    org_id: str


@dataclass
class ScimEndpointRequest(_Request):
    org_id: str


# -- SAML IdP (Authorizer as Identity Provider for downstream SPs) ----------- #
@dataclass
class CreateSAMLServiceProviderRequest(_Request):
    org_id: str
    name: str
    # entity_id: the SP entity ID (unique within the org).
    entity_id: str
    # acs_url: the SP Assertion Consumer Service URL (https recommended).
    acs_url: str
    sp_cert_pem: str | None = None
    # name_id_format: default urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress.
    name_id_format: str | None = None
    # mapped_attributes: JSON, e.g. {"email":"email","given_name":"firstName"}.
    mapped_attributes: str | None = None
    # allow_idp_initiated: default false (SP-initiated only).
    allow_idp_initiated: bool | None = None


@dataclass
class UpdateSAMLServiceProviderRequest(_Request):
    id: str
    name: str | None = None
    entity_id: str | None = None
    acs_url: str | None = None
    sp_cert_pem: str | None = None
    name_id_format: str | None = None
    mapped_attributes: str | None = None
    allow_idp_initiated: bool | None = None
    is_active: bool | None = None


@dataclass
class SAMLServiceProviderRequest(_Request):
    id: str


@dataclass
class ListSAMLServiceProvidersRequest(_Request):
    org_id: str
    pagination: PaginationRequest | None = None


@dataclass
class RotateSAMLIDPCertRequest(_Request):
    org_id: str


@dataclass
class RetireSAMLIDPKeyRequest(_Request):
    id: str


@dataclass
class ListSAMLIDPKeysRequest(_Request):
    org_id: str


@dataclass
class ImportSAMLSPMetadataRequest(_Request):
    # metadata_xml: pasted SP metadata XML (NOT a URL — no remote fetch).
    metadata_xml: str


# -- user organizations ------------------------------------------------------- #
@dataclass
class UserOrganizationsRequest(_Request):
    user_id: str
    pagination: PaginationRequest | None = None


# -- org domains (home-realm discovery) --------------------------------------- #
@dataclass
class RequestOrgDomainRequest(_Request):
    org_id: str
    domain: str


@dataclass
class VerifyOrgDomainRequest(_Request):
    org_id: str
    domain: str


@dataclass
class AddVerifiedOrgDomainRequest(_Request):
    org_id: str
    domain: str


@dataclass
class ListOrgDomainsRequest(_Request):
    org_id: str
    pagination: PaginationRequest | None = None


@dataclass
class DeleteOrgDomainRequest(_Request):
    domain: str


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


# Client is a registered OAuth client / service account. client_secret is
# NEVER part of this shape — it is returned exactly once in
# CreateClientResponse (creation and rotation) and never again.
@dataclass
class Client:
    id: str = ""
    # client_id is the public OAuth identifier presented at the authorize/token
    # endpoints, distinct from id (internal surrogate key).
    client_id: str = ""
    name: str = ""
    description: str | None = None
    allowed_scopes: list[str] = field(default_factory=list)
    is_active: bool = False
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Client:
        return cls(**_known(cls, data))


@dataclass
class CreateClientResponse:
    client: Client = field(default_factory=Client)
    # client_secret is returned ONCE at creation and ONCE at rotation. Store
    # it securely; it can never be retrieved again.
    client_secret: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CreateClientResponse:
        raw = data.get("client")
        return cls(
            client=Client.from_dict(raw) if isinstance(raw, dict) else Client(),
            client_secret=str(data.get("client_secret", "")),
        )


@dataclass
class ClientsResponse:
    clients: list[Client] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClientsResponse:
        raw = data.get("clients")
        items = raw if isinstance(raw, list) else []
        return cls(
            clients=[Client.from_dict(c) for c in items if isinstance(c, dict)],
            pagination=_pagination(data),
        )


@dataclass
class TrustedIssuer:
    id: str = ""
    service_account_id: str = ""
    name: str = ""
    issuer_url: str = ""
    key_source_type: str = ""
    jwks_url: str | None = None
    expected_aud: str = ""
    subject_claim: str = ""
    # allowed_subjects: comma-separated exact subject allow-list. Empty = deny-all.
    allowed_subjects: str | None = None
    issuer_type: str = ""
    is_active: bool = False
    spiffe_refresh_hint_seconds: int | None = None
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustedIssuer:
        return cls(**_known(cls, data))


@dataclass
class TrustedIssuersResponse:
    trusted_issuers: list[TrustedIssuer] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustedIssuersResponse:
        raw = data.get("trusted_issuers")
        items = raw if isinstance(raw, list) else []
        return cls(
            trusted_issuers=[TrustedIssuer.from_dict(x) for x in items if isinstance(x, dict)],
            pagination=_pagination(data),
        )


@dataclass
class Organization:
    id: str = ""
    # name is a unique, URL-safe slug identifying the organization.
    name: str = ""
    display_name: str | None = None
    enabled: bool = False
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Organization:
        return cls(**_known(cls, data))


@dataclass
class OrganizationsResponse:
    organizations: list[Organization] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrganizationsResponse:
        raw = data.get("organizations")
        items = raw if isinstance(raw, list) else []
        return cls(
            organizations=[Organization.from_dict(o) for o in items if isinstance(o, dict)],
            pagination=_pagination(data),
        )


@dataclass
class OrgMember:
    id: str = ""
    org_id: str = ""
    user_id: str = ""
    # Resolved user identity for display; blank when the user no longer exists.
    email: str | None = None
    given_name: str | None = None
    family_name: str | None = None
    # roles is the set of per-organization roles granted to this member.
    roles: list[str] = field(default_factory=list)
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrgMember:
        return cls(**_known(cls, data))


@dataclass
class OrgMembersResponse:
    org_members: list[OrgMember] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrgMembersResponse:
        raw = data.get("org_members")
        items = raw if isinstance(raw, list) else []
        return cls(
            org_members=[OrgMember.from_dict(m) for m in items if isinstance(m, dict)],
            pagination=_pagination(data),
        )


# OrgOIDCConnection: per-org upstream OIDC IdP brokered by Authorizer as a
# Relying Party. The upstream client_secret is NEVER projected here.
@dataclass
class OrgOIDCConnection:
    id: str = ""
    org_id: str = ""
    name: str = ""
    issuer_url: str = ""
    # sso_client_id: the client_id Authorizer uses AT the upstream IdP.
    sso_client_id: str = ""
    scopes: str | None = None
    redirect_uri: str | None = None
    is_active: bool = False
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrgOIDCConnection:
        return cls(**_known(cls, data))


# OrgSAMLConnection: per-org upstream SAML 2.0 IdP for which Authorizer acts
# as the Service Provider. The IdP signing certificate is never projected back.
@dataclass
class OrgSAMLConnection:
    id: str = ""
    org_id: str = ""
    name: str = ""
    idp_entity_id: str = ""
    idp_sso_url: str | None = None
    sp_entity_id: str | None = None
    acs_url: str | None = None
    attribute_mapping: str | None = None
    allow_idp_initiated: bool = False
    is_active: bool = False
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrgSAMLConnection:
        return cls(**_known(cls, data))


# ScimEndpoint: per-org inbound SCIM 2.0 connection. The bearer token is NEVER
# returned here; it is returned exactly once in CreateScimEndpointResponse.
@dataclass
class ScimEndpoint:
    id: str = ""
    org_id: str = ""
    enabled: bool = False
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ScimEndpoint:
        return cls(**_known(cls, data))


@dataclass
class CreateScimEndpointResponse:
    scim_endpoint: ScimEndpoint = field(default_factory=ScimEndpoint)
    # token is the bearer credential the org's IdP presents at /scim/v2/. It
    # is returned ONCE at creation and ONCE at rotation. Store it securely.
    token: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CreateScimEndpointResponse:
        raw = data.get("scim_endpoint")
        return cls(
            scim_endpoint=ScimEndpoint.from_dict(raw) if isinstance(raw, dict) else ScimEndpoint(),
            token=str(data.get("token", "")),
        )


# -- SAML IdP (Authorizer as Identity Provider for downstream SPs) ----------- #
@dataclass
class SAMLServiceProvider:
    id: str = ""
    org_id: str = ""
    name: str = ""
    entity_id: str = ""
    acs_url: str = ""
    sp_cert_pem: str | None = None
    name_id_format: str | None = None
    mapped_attributes: str | None = None
    allow_idp_initiated: bool = False
    is_active: bool = False
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SAMLServiceProvider:
        return cls(**_known(cls, data))


@dataclass
class SAMLServiceProvidersResponse:
    saml_service_providers: list[SAMLServiceProvider] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SAMLServiceProvidersResponse:
        raw = data.get("saml_service_providers")
        items = raw if isinstance(raw, list) else []
        return cls(
            saml_service_providers=[
                SAMLServiceProvider.from_dict(x) for x in items if isinstance(x, dict)
            ],
            pagination=_pagination(data),
        )


# SAMLIDPKey: per-org SAML IdP signing keypair. The private key is NEVER
# projected — only the certificate and rotation status.
@dataclass
class SAMLIDPKey:
    id: str = ""
    org_id: str = ""
    cert_pem: str = ""
    algorithm: str = ""
    # status: "current" (signs new assertions), "active" (published, not
    # signing), or "retired" (neither).
    status: str = ""
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SAMLIDPKey:
        return cls(**_known(cls, data))


@dataclass
class SAMLSPMetadataParseResult:
    entity_id: str = ""
    acs_url: str = ""
    certificate: str | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SAMLSPMetadataParseResult:
        return cls(**_known(cls, data))


# -- user organizations ------------------------------------------------------- #
@dataclass
class UserOrganization:
    organization: Organization = field(default_factory=Organization)
    roles: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserOrganization:
        raw = data.get("organization")
        raw_roles = data.get("roles")
        return cls(
            organization=Organization.from_dict(raw) if isinstance(raw, dict) else Organization(),
            roles=list(raw_roles) if isinstance(raw_roles, list) else [],
        )


@dataclass
class UserOrganizationsResponse:
    user_organizations: list[UserOrganization] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UserOrganizationsResponse:
        raw = data.get("user_organizations")
        items = raw if isinstance(raw, list) else []
        return cls(
            user_organizations=[
                UserOrganization.from_dict(x) for x in items if isinstance(x, dict)
            ],
            pagination=_pagination(data),
        )


# -- org domains (home-realm discovery) --------------------------------------- #
@dataclass
class OrgDomain:
    domain: str = ""
    org_id: str = ""
    verified_at: int | None = None
    created_at: int | None = None
    updated_at: int | None = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrgDomain:
        return cls(**_known(cls, data))


@dataclass
class OrgDomainsResponse:
    org_domains: list[OrgDomain] = field(default_factory=list)
    pagination: Pagination = field(default_factory=Pagination)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrgDomainsResponse:
        raw = data.get("org_domains")
        items = raw if isinstance(raw, list) else []
        return cls(
            org_domains=[OrgDomain.from_dict(x) for x in items if isinstance(x, dict)],
            pagination=_pagination(data),
        )


# OrgDomainChallenge is the DNS TXT record a tenant must publish to prove
# control of a domain. Returned by request_org_domain; no durable row exists
# until the domain is verified.
@dataclass
class OrgDomainChallenge:
    domain: str = ""
    # record_type is always "TXT".
    record_type: str = ""
    record_name: str = ""
    record_value: str = ""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OrgDomainChallenge:
        return cls(**_known(cls, data))
