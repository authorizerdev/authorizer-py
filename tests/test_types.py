from authorizer import types as t


def test_request_to_dict_drops_none():
    req = t.LoginRequest(password="Abc@123", email="a@b.com")
    assert req.to_dict() == {"password": "Abc@123", "email": "a@b.com"}


def test_request_to_dict_serializes_enum():
    req = t.ValidateJWTTokenRequest(token="x", token_type=t.TokenType.ACCESS_TOKEN)
    assert req.to_dict() == {"token": "x", "token_type": "access_token"}


def test_request_to_dict_nested_dataclasses():
    req = t.CheckPermissionsRequest(
        checks=[t.PermissionCheckInput(relation="can_view", object="document:1")],
        user="user:alice",
    )
    assert req.to_dict() == {
        "checks": [{"relation": "can_view", "object": "document:1"}],
        "user": "user:alice",
    }


def test_user_from_dict_tolerates_extra_keys():
    user = t.User.from_dict({"id": "1", "email": "a@b.com", "unknown_field": "x"})
    assert user.id == "1"
    assert user.email == "a@b.com"


def test_auth_token_from_dict_parses_nested_user():
    tok = t.AuthToken.from_dict(
        {"access_token": "tok", "user": {"id": "1", "email": "a@b.com"}}
    )
    assert tok.access_token == "tok"
    assert tok.user is not None
    assert tok.user.id == "1"


def test_check_permissions_response_from_dict():
    resp = t.CheckPermissionsResponse.from_dict(
        {"results": [{"relation": "can_view", "object": "document:1", "allowed": True}]}
    )
    assert resp.results[0].allowed is True
    assert resp.results[0].object == "document:1"


def test_list_permissions_response_from_dict():
    resp = t.ListPermissionsResponse.from_dict(
        {
            "objects": ["document:1"],
            "permissions": [{"object": "document:1", "relation": "can_view"}],
            "truncated": False,
        }
    )
    assert resp.objects == ["document:1"]
    assert resp.permissions[0].relation == "can_view"
    assert resp.truncated is False
