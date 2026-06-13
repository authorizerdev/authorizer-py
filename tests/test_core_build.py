from authorizer._core import (
    ClientConfig,
    RequestSpec,
    build_graphql_request,
    build_headers,
    build_oauth_request,
)


def _config():
    return ClientConfig(
        client_id="cid",
        authorizer_url="https://auth.example.com",
        redirect_url="",
        extra_headers={},
    )


def test_build_headers_sets_identity_and_origin():
    headers = build_headers(_config(), None)
    assert headers["x-authorizer-url"] == "https://auth.example.com"
    assert headers["x-authorizer-client-id"] == "cid"
    assert headers["Origin"] == "https://auth.example.com"
    assert headers["Content-Type"] == "application/json"


def test_build_headers_merges_extra_and_per_call():
    cfg = ClientConfig("cid", "https://auth.example.com", "", {"X-Extra": "1"})
    headers = build_headers(cfg, {"Authorization": "Bearer t"})
    assert headers["X-Extra"] == "1"
    assert headers["Authorization"] == "Bearer t"


def test_per_call_origin_overrides_default():
    headers = build_headers(_config(), {"Origin": "https://app.example.com"})
    assert headers["Origin"] == "https://app.example.com"


def test_build_graphql_request_shape():
    spec = build_graphql_request(
        "https://auth.example.com", "query { x }", {"data": {"a": 1}}, {"H": "v"}
    )
    assert isinstance(spec, RequestSpec)
    assert spec.method == "POST"
    assert spec.url == "https://auth.example.com/graphql"
    assert spec.json == {"query": "query { x }", "variables": {"data": {"a": 1}}}
    assert spec.headers == {"H": "v"}


def test_build_graphql_request_omits_empty_variables():
    spec = build_graphql_request("https://auth.example.com", "query { x }", None, {})
    assert spec.json == {"query": "query { x }"}


def test_build_oauth_request_shape():
    spec = build_oauth_request(
        "https://auth.example.com", "/oauth/token", {"client_id": "cid"}, {"H": "v"}
    )
    assert spec.url == "https://auth.example.com/oauth/token"
    assert spec.json == {"client_id": "cid"}
