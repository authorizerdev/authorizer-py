import json

import respx
from httpx import Response

from authorizer.client import AuthorizerClient


@respx.mock
def test_login_returns_auth_token():
    payload = {
        "data": {
            "login": {
                "access_token": "tok",
                "user": {"id": "1", "email": "a@b.com"},
            }
        }
    }
    route = respx.post("https://auth.example.com/graphql").mock(
        return_value=Response(200, json=payload)
    )
    with AuthorizerClient("cid", "https://auth.example.com") as c:
        tok = c.login_from(email="a@b.com", password="Abc@123")
    assert tok.access_token == "tok"
    assert tok.user.id == "1"
    sent = json.loads(route.calls[0].request.content)
    assert sent["variables"]["data"] == {"email": "a@b.com", "password": "Abc@123"}
    assert route.calls[0].request.headers["x-authorizer-client-id"] == "cid"
    assert route.calls[0].request.headers["origin"] == "https://auth.example.com"
