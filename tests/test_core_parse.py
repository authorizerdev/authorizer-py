# tests/test_core_parse.py
import pytest

from authorizer._core import parse_graphql_response, parse_oauth_response
from authorizer.exceptions import AuthorizerError


def test_parse_graphql_returns_field():
    body = b'{"data": {"login": {"access_token": "tok"}}}'
    assert parse_graphql_response(200, body, "login") == {"access_token": "tok"}


def test_parse_graphql_raises_on_errors_array():
    body = b'{"errors": [{"message": "bad creds"}], "data": null}'
    with pytest.raises(AuthorizerError) as exc:
        parse_graphql_response(200, body, "login")
    assert "bad creds" in str(exc.value)


def test_parse_graphql_raises_on_http_error_without_errors_array():
    # e.g. CSRF 403 / proxy error page carrying no GraphQL "errors"
    body = b"Forbidden"
    with pytest.raises(AuthorizerError) as exc:
        parse_graphql_response(403, body, "login")
    assert exc.value.status == 403


def test_parse_graphql_returns_none_field_when_absent():
    body = b'{"data": {}}'
    assert parse_graphql_response(200, body, "login") is None


def test_parse_oauth_returns_json():
    body = b'{"access_token": "tok", "expires_in": 3600}'
    assert parse_oauth_response(200, body) == {"access_token": "tok", "expires_in": 3600}


def test_parse_oauth_raises_with_error_description():
    body = b'{"error": "invalid_grant", "error_description": "expired"}'
    with pytest.raises(AuthorizerError) as exc:
        parse_oauth_response(400, body)
    assert "expired" in str(exc.value)
    assert exc.value.status == 400


def test_parse_graphql_returns_none_when_data_is_null():
    body = b'{"data": null}'
    assert parse_graphql_response(200, body, "logout") is None


def test_parse_graphql_forwards_string_errors_message():
    body = b'{"errors": "bad input", "data": null}'
    with pytest.raises(AuthorizerError) as exc:
        parse_graphql_response(200, body, "login")
    assert "bad input" in str(exc.value)


def test_parse_oauth_empty_body_returns_empty_dict():
    assert parse_oauth_response(200, b"") == {}
