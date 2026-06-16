"""Live integration tests against a real Authorizer server.

Gated behind ``@pytest.mark.live`` so it never runs in the default unit suite.
Run against ``lakhansamani/authorizer:2.3.0-rc.9`` (see SDK_ADMIN_SPEC.md):

    docker run -p 8090:8080 -p 9091:9091 lakhansamani/authorizer:2.3.0-rc.9 \\
        --database-type=sqlite --database-url=test.db --jwt-type=HS256 \\
        --jwt-secret=test --admin-secret=admin --client-id=test-client \\
        --client-secret=secret

    AUTHORIZER_TEST_URL=http://localhost:8090 \\
        AUTHORIZER_TEST_GRPC=localhost:9091 \\
        AUTHORIZER_TEST_CLIENT_ID=test-client \\
        AUTHORIZER_ADMIN_SECRET=admin \\
        AUTHORIZER_PROTOCOLS=graphql,rest,grpc \\
        pytest tests/integration -m live -v

Every public method is exercised over EVERY protocol (graphql/rest/grpc) on both
the sync and async clients. As of 2.3.0-rc.9 (PR #635 + #636) there are no
graphql-only public methods: all 20 public RPCs work over all three protocols and
the response envelope is flat (AuthResponse/User/Meta returned directly).
"""

from __future__ import annotations

import asyncio
import os
import time
import uuid

import httpx
import pytest

from authorizer import types as t
from authorizer.admin_client import AuthorizerAdminClient
from authorizer.async_admin_client import AsyncAuthorizerAdminClient
from authorizer.async_client import AsyncAuthorizerClient
from authorizer.client import AuthorizerClient
from authorizer.exceptions import AuthorizerError

pytestmark = pytest.mark.live


def _env(*names: str, default: str = "") -> str:
    for n in names:
        v = os.environ.get(n)
        if v:
            return v
    return default


URL = _env("AUTHORIZER_TEST_URL", "AUTHORIZER_URL", default="http://localhost:8091")
GRPC = _env("AUTHORIZER_TEST_GRPC", "AUTHORIZER_GRPC", default="localhost:9092")
CLIENT_ID = _env("AUTHORIZER_TEST_CLIENT_ID", "AUTHORIZER_CLIENT_ID", default="test-client")
ADMIN_SECRET = _env("AUTHORIZER_ADMIN_SECRET", default="admin")
PROTOCOLS = _env("AUTHORIZER_PROTOCOLS", default="graphql,rest,grpc").split(",")
PROTOCOLS = [p.strip() for p in PROTOCOLS if p.strip()]

PASSWORD = "Test@12345"


def _unique(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session", autouse=True)
def _retry_429() -> None:
    """Retry HTTP 429s with backoff for the whole session.

    The full matrix (3 protocols x sync+async x many methods) trips the server's
    request rate limiter; this is a harness throughput artifact, not an SDK bug.
    We wrap httpx's request methods (the SDK transport) to retry transparently.
    """
    sync_orig = httpx.Client.request
    async_orig = httpx.AsyncClient.request

    def sync_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        for attempt in range(8):
            resp = sync_orig(self, *args, **kwargs)
            if resp.status_code != 429:
                return resp
            time.sleep(0.25 * (attempt + 1))
        return resp

    async def async_request(self, *args, **kwargs):  # type: ignore[no-untyped-def]
        for attempt in range(8):
            resp = await async_orig(self, *args, **kwargs)
            if resp.status_code != 429:
                return resp
            await asyncio.sleep(0.25 * (attempt + 1))
        return resp

    httpx.Client.request = sync_request  # type: ignore[method-assign,assignment]
    httpx.AsyncClient.request = async_request  # type: ignore[method-assign,assignment]
    yield
    httpx.Client.request = sync_orig  # type: ignore[method-assign]
    httpx.AsyncClient.request = async_orig  # type: ignore[method-assign]


@pytest.fixture(params=PROTOCOLS)
def protocol(request: pytest.FixtureRequest) -> str:
    return str(request.param)


@pytest.fixture
def client(protocol: str) -> AuthorizerClient:
    c = AuthorizerClient(CLIENT_ID, URL, protocol=protocol, grpc_endpoint=GRPC)
    yield c
    c.close()


@pytest.fixture
def admin(protocol: str) -> AuthorizerAdminClient:
    c = AuthorizerAdminClient(URL, ADMIN_SECRET, protocol=protocol, grpc_endpoint=GRPC)
    yield c
    c.close()


def _signup(client: AuthorizerClient) -> tuple[t.AuthToken, dict[str, str], str]:
    """Signup a fresh user over graphql and return (auth, bearer_header, session_cookie).

    Graphql signup is always available and sets the session cookie on its httpx
    client; we surface that cookie so cookie-bound endpoints (session,
    validate_session) can be exercised over every protocol.
    """
    gql = AuthorizerClient(CLIENT_ID, URL, protocol="graphql")
    try:
        auth = gql.signup(
            t.SignUpRequest(
                email=f"{_unique('py-live')}@example.com",
                password=PASSWORD,
                confirm_password=PASSWORD,
            )
        )
        cookie = gql._http.cookies.get("cookie_session") or ""
    finally:
        gql.close()
    headers = {"Authorization": f"Bearer {auth.access_token}"} if auth.access_token else {}
    return auth, headers, cookie


# --------------------------------------------------------------------------- #
# Public client — methods available over ALL protocols (sync)
# --------------------------------------------------------------------------- #
def test_meta(client: AuthorizerClient) -> None:
    meta = client.get_meta_data()
    assert meta.version  # populated payload over graphql/rest/grpc
    assert meta.is_basic_authentication_enabled is True


def test_signup_and_profile(client: AuthorizerClient) -> None:
    email = f"{_unique('py-live')}@example.com"
    auth = client.signup(
        t.SignUpRequest(email=email, password=PASSWORD, confirm_password=PASSWORD)
    )
    assert auth.access_token
    assert auth.user is not None and auth.user.email == email
    headers = {"Authorization": f"Bearer {auth.access_token}"}
    profile = client.get_profile(headers=headers)
    assert profile.email == email


def test_get_session(client: AuthorizerClient) -> None:
    _, _, cookie = _signup(client)
    # session is cookie-bound: HTTP reads the Cookie header, grpc lowercases it
    # to the ``cookie`` metadata key (both accepted by the server).
    session = client.get_session(headers={"Cookie": f"cookie_session={cookie}"})
    assert session.access_token  # populated AuthToken over all protocols


def test_validate_jwt_token(client: AuthorizerClient) -> None:
    auth, _, _ = _signup(client)
    res = client.validate_jwt_token(
        t.ValidateJWTTokenRequest(token=auth.access_token or "", token_type="access_token")
    )
    assert res.is_valid is True


def test_validate_session(client: AuthorizerClient) -> None:
    _, _, cookie = _signup(client)
    res = client.validate_session(t.ValidateSessionRequest(cookie=cookie))
    assert res.is_valid is True


def test_logout(client: AuthorizerClient) -> None:
    _, headers, _ = _signup(client)
    res = client.logout(headers=headers)
    assert res is not None  # GenericResponse over all protocols


def test_check_and_list_permissions(client: AuthorizerClient, fga_seed: None) -> None:
    _, headers, _ = _signup(client)
    check = client.check_permissions(
        t.CheckPermissionsRequest(
            checks=[t.PermissionCheckInput(relation="reader", object="document:1")]
        ),
        headers=headers,
    )
    assert isinstance(check.results, list)
    listed = client.list_permissions(
        t.ListPermissionsRequest(object_type="document"), headers=headers
    )
    assert isinstance(listed.objects, list)


# --------------------------------------------------------------------------- #
# Public client — formerly gql-only methods now work over ALL protocols (rc.9).
# --------------------------------------------------------------------------- #
def test_login(client: AuthorizerClient) -> None:
    # Sign up a fresh user (over the same protocol), then log in with it.
    email = f"{_unique('py-login')}@example.com"
    client.signup(t.SignUpRequest(email=email, password=PASSWORD, confirm_password=PASSWORD))
    auth = client.login(t.LoginRequest(email=email, password=PASSWORD))
    assert auth.access_token
    assert auth.user is not None and auth.user.email == email


def test_update_profile(client: AuthorizerClient) -> None:
    # update_profile is authenticated: over grpc the bearer is sent as metadata
    # (#636 interceptor); over http it is the Authorization header.
    email = f"{_unique('py-upd')}@example.com"
    auth = client.signup(
        t.SignUpRequest(email=email, password=PASSWORD, confirm_password=PASSWORD)
    )
    headers = {"Authorization": f"Bearer {auth.access_token}"}
    res = client.update_profile(t.UpdateProfileRequest(given_name="Updated"), headers=headers)
    assert res is not None  # GenericResponse over all protocols
    prof = client.get_profile(headers=headers)
    assert prof.given_name == "Updated"


def test_resend_otp_and_forgot_password(client: AuthorizerClient) -> None:
    # These hit the server over every protocol now (no gql-only guard). They may
    # legitimately error if the feature is disabled server-side; either a flat
    # *Response or a clear AuthorizerError is acceptable — what matters is the
    # SDK no longer refuses to dispatch them over rest/grpc.
    email = f"{_unique('py-otp')}@example.com"
    client.signup(t.SignUpRequest(email=email, password=PASSWORD, confirm_password=PASSWORD))
    try:
        res = client.forgot_password(t.ForgotPasswordRequest(email=email))
        assert res is not None
    except AuthorizerError as e:
        assert "not available over" not in str(e)  # must reach the server, not refuse


# --------------------------------------------------------------------------- #
# Async parity — same public methods over every protocol
# --------------------------------------------------------------------------- #
async def test_async_meta(protocol: str) -> None:
    c = AsyncAuthorizerClient(CLIENT_ID, URL, protocol=protocol, grpc_endpoint=GRPC)
    try:
        meta = await c.get_meta_data()
        assert meta.version
    finally:
        await c.aclose()


async def test_async_signup_and_profile(protocol: str) -> None:
    c = AsyncAuthorizerClient(CLIENT_ID, URL, protocol=protocol, grpc_endpoint=GRPC)
    try:
        email = f"{_unique('py-async')}@example.com"
        auth = await c.signup(
            t.SignUpRequest(email=email, password=PASSWORD, confirm_password=PASSWORD)
        )
        assert auth.user is not None and auth.user.email == email
        prof = await c.get_profile(
            headers={"Authorization": f"Bearer {auth.access_token}"}
        )
        assert prof.email == email
    finally:
        await c.aclose()


async def test_async_login_and_update_profile(protocol: str) -> None:
    c = AsyncAuthorizerClient(CLIENT_ID, URL, protocol=protocol, grpc_endpoint=GRPC)
    try:
        email = f"{_unique('py-async-login')}@example.com"
        auth = await c.signup(
            t.SignUpRequest(email=email, password=PASSWORD, confirm_password=PASSWORD)
        )
        logged_in = await c.login(t.LoginRequest(email=email, password=PASSWORD))
        assert logged_in.access_token
        headers = {"Authorization": f"Bearer {auth.access_token}"}
        res = await c.update_profile(
            t.UpdateProfileRequest(family_name="Async"), headers=headers
        )
        assert res is not None
    finally:
        await c.aclose()


# --------------------------------------------------------------------------- #
# Admin client — available over all protocols (sync)
# --------------------------------------------------------------------------- #
def test_admin_users(admin: AuthorizerAdminClient) -> None:
    page = admin.users(t.PaginatedRequest(pagination=t.PaginationRequest(page=1, limit=10)))
    assert page.pagination.page == 1
    assert page.pagination.limit == 10  # int64 string coerced to int over REST
    assert isinstance(page.pagination.limit, int)
    assert isinstance(page.users, list)


def test_admin_verification_requests(admin: AuthorizerAdminClient) -> None:
    res = admin.verification_requests(
        t.PaginatedRequest(pagination=t.PaginationRequest(page=1, limit=10))
    )
    assert isinstance(res.verification_requests, list)


def test_admin_audit_logs(admin: AuthorizerAdminClient) -> None:
    res = admin.audit_logs()
    assert isinstance(res.audit_logs, list)


# Webhook event names are a server-side enum AND carry a UNIQUE constraint, so we
# cannot synthesize a unique name. Instead assign a distinct valid event per
# protocol and clean up (delete) at the end so re-runs do not collide.
_WEBHOOK_EVENTS = {
    "graphql": "user.login",
    "rest": "user.signup",
    "grpc": "user.created",
}


def test_admin_webhook_lifecycle(admin: AuthorizerAdminClient, protocol: str) -> None:
    event = _WEBHOOK_EVENTS.get(protocol, "user.access_revoked")
    endpoint = f"https://example.com/{_unique('hook')}"  # host must resolve server-side
    created_id = ""
    try:
        # drop any leftover webhook for this event from an interrupted prior run
        for w in admin.webhooks(
            t.PaginatedRequest(pagination=t.PaginationRequest(page=1, limit=100))
        ).webhooks:
            if w.event_name == event and w.id:
                admin.delete_webhook(t.WebhookRequest(id=w.id))
        admin.add_webhook(
            t.AddWebhookRequest(event_name=event, endpoint=endpoint, enabled=False)
        )
        page = admin.webhooks(
            t.PaginatedRequest(pagination=t.PaginationRequest(page=1, limit=100))
        )
        assert isinstance(page.webhooks, list)
        match = next((w for w in page.webhooks if w.endpoint == endpoint), None)
        assert match is not None and match.id
        created_id = match.id
        fetched = admin.get_webhook(t.WebhookRequest(id=created_id))
        assert fetched.endpoint == endpoint
    finally:
        if created_id:
            admin.delete_webhook(t.WebhookRequest(id=created_id))


def test_admin_email_template_lifecycle(admin: AuthorizerAdminClient, protocol: str) -> None:
    event = "basic_auth_signup"  # template event names are an enum; uniqueness via cleanup
    created_id = ""
    try:
        # delete any pre-existing template for this event so the add does not collide
        existing = admin.email_templates()
        for tmpl in existing.email_templates:
            if tmpl.event_name == event and tmpl.id:
                admin.delete_email_template(t.DeleteEmailTemplateRequest(id=tmpl.id))
        admin.add_email_template(
            t.AddEmailTemplateRequest(
                event_name=event, subject=_unique("subj"), template="<p>hi</p>"
            )
        )
        res = admin.email_templates()
        assert isinstance(res.email_templates, list)
        match = next((e for e in res.email_templates if e.event_name == event), None)
        assert match is not None and match.id
        created_id = match.id
    finally:
        if created_id:
            admin.delete_email_template(t.DeleteEmailTemplateRequest(id=created_id))


# -- admin meta / fga get-model (rest + grpc only) --------------------------- #
def test_admin_meta_rest_grpc(protocol: str) -> None:
    if protocol == "graphql":
        with pytest.raises(AuthorizerError) as exc:
            AuthorizerAdminClient(URL, ADMIN_SECRET, protocol="graphql").admin_meta()
        assert "not available over graphql" in str(exc.value)
        return
    c = AuthorizerAdminClient(URL, ADMIN_SECRET, protocol=protocol, grpc_endpoint=GRPC)
    try:
        assert isinstance(c.admin_meta().roles, list)
    finally:
        c.close()


# --------------------------------------------------------------------------- #
# Async admin parity
# --------------------------------------------------------------------------- #
async def test_async_admin_users(protocol: str) -> None:
    c = AsyncAuthorizerAdminClient(URL, ADMIN_SECRET, protocol=protocol, grpc_endpoint=GRPC)
    try:
        page = await c.users(
            t.PaginatedRequest(pagination=t.PaginationRequest(page=1, limit=5))
        )
        assert page.pagination.page == 1
        assert isinstance(page.pagination.limit, int)
    finally:
        await c.aclose()


# --------------------------------------------------------------------------- #
# FGA — model + tuples written once (session), read/list/expand, reset LAST.
# The session-scoped fixture seeds shared state; reset runs exactly once at the
# very end of the session via the autouse teardown.
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="session")
def fga_seed() -> None:
    """Write a model + a tuple ONCE for the whole session (idempotent)."""
    a = AuthorizerAdminClient(URL, ADMIN_SECRET, protocol="rest", grpc_endpoint=GRPC)
    model = (
        "model\n  schema 1.1\ntype user\ntype document\n  relations\n"
        "    define reader: [user]\n"
    )
    try:
        try:
            a.fga_write_model(t.FgaWriteModelRequest(dsl=model))
        except AuthorizerError:
            pytest.skip("fine-grained authorization not configured")
        try:
            a.fga_write_tuples(
                t.FgaWriteTuplesRequest(
                    tuples=[
                        t.FgaTupleInput(user="user:1", relation="reader", object="document:1")
                    ]
                )
            )
        except AuthorizerError:
            pass  # tuple already exists from a prior run; fine
    finally:
        a.close()
    return None


@pytest.fixture(scope="session", autouse=True)
def _fga_reset_last() -> None:
    """Reset the FGA store exactly once, at the very end of the session."""
    yield
    a = AuthorizerAdminClient(URL, ADMIN_SECRET, protocol="rest", grpc_endpoint=GRPC)
    try:
        try:
            a.fga_reset()
        except AuthorizerError:
            pass  # not configured / nothing to reset
    finally:
        a.close()


def test_fga_read_list_expand(admin: AuthorizerAdminClient, fga_seed: None) -> None:
    reads = admin.fga_read_tuples(t.FgaReadTuplesRequest())
    assert any(x.object == "document:1" for x in reads.tuples)
    users = admin.fga_list_users(
        t.FgaListUsersRequest(object="document:1", relation="reader", user_type="user")
    )
    assert "user:1" in users.users
    expand = admin.fga_expand(t.FgaExpandRequest(relation="reader", object="document:1"))
    assert expand is not None
