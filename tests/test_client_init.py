import pytest

from authorizer.client import AuthorizerClient


def test_requires_client_id():
    with pytest.raises(ValueError):
        AuthorizerClient(client_id="", authorizer_url="https://auth.example.com")


def test_requires_authorizer_url():
    with pytest.raises(ValueError):
        AuthorizerClient(client_id="cid", authorizer_url="  ")


def test_trims_trailing_slash():
    c = AuthorizerClient(client_id="cid", authorizer_url="https://auth.example.com/")
    assert c._config.authorizer_url == "https://auth.example.com"
    c.close()


def test_context_manager_closes():
    with AuthorizerClient(client_id="cid", authorizer_url="https://auth.example.com") as c:
        assert c._config.client_id == "cid"
    assert c._http.is_closed
