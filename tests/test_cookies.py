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


def test_remote_host_cannot_plant_a_loopback_cookie():
    """A non-loopback origin must not be able to set a localhost-scoped cookie.

    The loopback relaxation exists so a local Authorizer's MFA session survives
    between calls. Keyed on the COOKIE's Domain instead of the REQUEST's host it
    would be an open door: any origin could reply

        Set-Cookie: mfa_session=attacker-chosen; Domain=localhost

    and the jar would store it, then hand it to the next http://localhost call —
    session fixation into the MFA session, from any server the SDK happens to
    talk to. Gate on the request host.
    """
    import httpx
    from httpx._models import Cookies

    from authorizer._core import new_cookie_jar

    jar = Cookies()
    jar.jar = new_cookie_jar()
    resp = httpx.Response(
        200,
        headers={"set-cookie": "mfa_session=STOLEN; Path=/; Domain=localhost"},
        request=httpx.Request("POST", "https://evil.example.com/x"),
    )
    jar.extract_cookies(resp)
    assert len(jar.jar) == 0, "a remote origin must not store a loopback cookie"


def test_remote_secure_cookie_is_not_downgraded():
    """The Secure->False rewrite must stay loopback-only.

    Dropping Secure on a real host's cookie would let it ride an http:// request
    — exactly what the attribute exists to prevent (RFC 6265 §4.1.2.5).
    """
    import httpx
    from httpx._models import Cookies

    from authorizer._core import new_cookie_jar

    jar = Cookies()
    jar.jar = new_cookie_jar()
    resp = httpx.Response(
        200,
        headers={"set-cookie": "sess=x; Path=/; Domain=auth.example.com; Secure"},
        request=httpx.Request("POST", "https://auth.example.com/graphql"),
    )
    jar.extract_cookies(resp)
    stored = list(jar.jar)
    assert stored, "a normal https cookie must still be stored"
    assert stored[0].secure is True, "Secure must survive for a non-loopback host"

    client = httpx.Client(cookies=jar.jar)
    req = client.build_request("GET", "http://auth.example.com/x")
    assert req.headers.get("cookie") is None, "a Secure cookie must not ride http://"
