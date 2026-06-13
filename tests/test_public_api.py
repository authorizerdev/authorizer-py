# tests/test_public_api.py
import authorizer


def test_top_level_exports():
    assert hasattr(authorizer, "AuthorizerClient")
    assert hasattr(authorizer, "AsyncAuthorizerClient")
    assert hasattr(authorizer, "AuthorizerError")
    assert hasattr(authorizer, "LoginRequest")
    assert hasattr(authorizer, "AuthToken")
    assert hasattr(authorizer, "TokenType")
    assert authorizer.TokenType.ACCESS_TOKEN.value == "access_token"


def test_dunder_all_is_importable():
    for name in authorizer.__all__:
        assert hasattr(authorizer, name), f"__all__ lists missing {name}"
