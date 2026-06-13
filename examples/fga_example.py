"""Fine-grained authorization (FGA) example."""

from authorizer import (
    AuthorizerClient,
    CheckPermissionsRequest,
    ListPermissionsRequest,
    PermissionCheckInput,
)

client = AuthorizerClient("YOUR_CLIENT_ID", "https://your-instance.authorizer.dev")
auth = {"Authorization": "Bearer USER_ACCESS_TOKEN"}

checks = client.check_permissions(
    CheckPermissionsRequest(
        checks=[
            PermissionCheckInput(relation="can_view", object="document:1"),
            PermissionCheckInput(relation="can_edit", object="document:1"),
        ]
    ),
    headers=auth,
)
for r in checks.results:
    print(r.relation, r.object, r.allowed)

accessible = client.list_permissions(
    ListPermissionsRequest(relation="can_view", object_type="document"), headers=auth
)
print("can view:", accessible.objects)
client.close()
