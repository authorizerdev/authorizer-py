from authorizer import _queries as q


def test_user_fragment_has_core_fields():
    assert "id" in q.USER_FRAGMENT
    assert "email" in q.USER_FRAGMENT


def test_auth_token_fragment_embeds_user_fragment():
    assert "access_token" in q.AUTH_TOKEN_FRAGMENT
    assert q.USER_FRAGMENT in q.AUTH_TOKEN_FRAGMENT


def test_login_query_uses_auth_token_fragment():
    assert "login(params: $data)" in q.LOGIN
    assert "access_token" in q.LOGIN


def test_check_permissions_query_shape():
    assert "check_permissions(params: $data)" in q.CHECK_PERMISSIONS
    assert "results { relation object allowed }" in q.CHECK_PERMISSIONS
