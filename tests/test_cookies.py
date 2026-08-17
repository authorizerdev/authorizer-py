# tests/test_cookies.py
import respx
from httpx import Response

from authorizer import types as t
from authorizer.client import AuthorizerClient

# What the server sends on an MFA offer: Secure (--app-cookie-secure defaults to
# true) and Domain-scoped to the host, even when served over plain http.
MFA_COOKIE = "mfa_session=sess-1; Path=/; Domain={host}; Max-Age=179; HttpOnly; Secure"

OFFER = {"data": {"signup": {"message": "Proceed to mfa setup", "access_token": None}}}
SKIPPED = {"data": {"skip_mfa_setup": {"message": "MFA setup skipped", "access_token": "tok"}}}


def _run(url, host):
    """Signup (MFA offer + Set-Cookie) then skip_mfa_setup; return the sent Cookie header."""
    with respx.mock:
        route = respx.post(f"{url}/graphql")
        route.side_effect = [
            Response(200, json=OFFER, headers={"set-cookie": MFA_COOKIE.format(host=host)}),
            Response(200, json=SKIPPED),
        ]
        client = AuthorizerClient("cid", url)
        try:
            offer = client.signup(
                t.SignUpRequest(email="a@b.com", password="p", confirm_password="p")
            )
            assert offer.access_token is None
            token = client.skip_mfa_setup(t.SkipMfaSetupRequest(email="a@b.com"))
        finally:
            client.close()
        return route.calls[1].request.headers.get("cookie"), token


def test_mfa_session_cookie_is_returned_over_http_localhost():
    # Regression: a Secure, Domain=localhost cookie is dropped by http.cookiejar
    # (Secure vs http, and dotless host -> "localhost.local"), so skip_mfa_setup
    # could never redeem the withheld token against a local server.
    cookie, token = _run("http://localhost:8380", "localhost")
    assert cookie == "mfa_session=sess-1"
    assert token.access_token == "tok"


def test_mfa_session_cookie_is_returned_over_https():
    cookie, token = _run("https://auth.example.com", "auth.example.com")
    assert cookie == "mfa_session=sess-1"
    assert token.access_token == "tok"


def test_secure_cookie_is_not_downgraded_for_non_loopback_hosts():
    # Only loopback gets the browser-style relaxation; a Secure cookie from a
    # real host must still never be sent over plain http.
    cookie, _ = _run("http://auth.example.com", "auth.example.com")
    assert cookie is None


def test_grpc_cookies_round_trip():
    # gRPC has no cookie jar: the server serialises cookies as `set-cookie`
    # response metadata and reads them back from a `cookie` entry.
    from authorizer._grpc_transport import apply_cookies, store_cookies

    jar: dict[str, str] = {}
    assert apply_cookies([("x", "1")], jar) == [("x", "1")]

    store_cookies(
        [
            ("content-type", "application/grpc"),
            ("set-cookie", MFA_COOKIE.format(host="localhost")),
        ],
        jar,
    )
    assert apply_cookies([("x", "1")], jar) == [("x", "1"), ("cookie", "mfa_session=sess-1")]

    # Max-Age<=0 is the server deleting the cookie (logout / DeleteMfaSession).
    store_cookies([("set-cookie", "mfa_session=; Path=/; Max-Age=-1")], jar)
    assert jar == {}


def test_cookies_are_only_sent_to_the_clients_own_origin():
    """The store is replayed to ONE origin, and that is structural.

    A cookie jar enforces domain scoping for free; a plain store does not, so the
    scoping has to come from somewhere else. Here it is construction: every
    RequestSpec is built from config.authorizer_url, so there is no code path
    that attaches the store to another host. This pins that — if someone ever
    threads a caller-supplied URL through _send, the MFA session would start
    leaving for hosts the developer never configured.
    """
    import respx
    from httpx import Response

    from authorizer import types as t
    from authorizer.client import AuthorizerClient

    with respx.mock(assert_all_called=False) as mock:
        mock.post("http://localhost:8380/graphql").mock(
            side_effect=[
                Response(
                    200,
                    json=OFFER,
                    headers={"set-cookie": MFA_COOKIE.format(host="localhost")},
                ),
                Response(200, json=SKIPPED),
            ]
        )
        other = mock.post("http://other.example.com/graphql").mock(
            return_value=Response(200, json=SKIPPED)
        )
        client = AuthorizerClient("cid", "http://localhost:8380")
        try:
            client.signup(t.SignUpRequest(email="a@b.com", password="p", confirm_password="p"))
            # Sanity: the handle was captured and is replayed to its own origin.
            client.skip_mfa_setup(t.SkipMfaSetupRequest(email="a@b.com"))
            assert client._cookies.get("mfa_session") == "sess-1"
        finally:
            client.close()
        assert not other.called, (
            "the client must never be able to send its cookie store to another host"
        )


def test_secure_cookie_is_not_stored_for_an_insecure_origin():
    """Secure must still mean something (RFC 6265 4.1.2.5).

    Without a jar there is no policy engine enforcing this, so it is enforced at
    capture instead: a Secure cookie is not recorded when the client's own origin
    is plain http and not loopback. Loopback is excepted because Secure Contexts
    makes it trustworthy — the same call Chrome, Firefox and Go's stdlib jar make.
    """
    from authorizer._core import absorb_set_cookie, origin_is_secure

    insecure: dict[str, str] = {}
    absorb_set_cookie(
        ["s=x; Path=/; Secure"],
        insecure,
        origin_is_secure=origin_is_secure("http://auth.example.com"),
    )
    assert insecure == {}, "a Secure cookie must not be stored for an http:// origin"

    for trusted in ("https://auth.example.com", "http://localhost:8380", "http://127.0.0.1:9000"):
        store: dict[str, str] = {}
        absorb_set_cookie(
            ["s=x; Path=/; Secure"], store, origin_is_secure=origin_is_secure(trusted)
        )
        assert store == {"s": "x"}, f"{trusted} must be able to carry a Secure cookie"


def test_server_deleting_a_cookie_clears_it():
    """Logout / DeleteMfaSession send Max-Age=0; the store must honour it.

    A jar expires entries on its own. This one does not, so a deletion that was
    ignored would leave the SDK replaying a dead handle forever — harmless to the
    server, which rejects it, but it would mask a completed logout locally.
    """
    from authorizer._core import absorb_set_cookie

    store: dict[str, str] = {}
    absorb_set_cookie(["mfa_session=sess-1; Path=/"], store)
    assert store == {"mfa_session": "sess-1"}
    absorb_set_cookie(["mfa_session=; Path=/; Max-Age=0"], store)
    assert store == {}, "a Max-Age=0 delete must drop the stored value"
