from authorizer.exceptions import AuthorizerConnectionError, AuthorizerError


def test_authorizer_error_carries_message_and_metadata():
    err = AuthorizerError("boom", errors=["a", "b"], status=403)
    assert str(err) == "boom"
    assert err.message == "boom"
    assert err.errors == ["a", "b"]
    assert err.status == 403


def test_authorizer_error_defaults():
    err = AuthorizerError("oops")
    assert err.errors == []
    assert err.status is None


def test_connection_error_is_authorizer_error():
    assert issubclass(AuthorizerConnectionError, AuthorizerError)
