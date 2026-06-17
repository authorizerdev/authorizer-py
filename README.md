# authorizer-python

Python SDK for [authorizer.dev](https://authorizer.dev) — self-hosted authentication & authorization. Current version: **0.2.0**.

## Getting Started

You need a running Authorizer instance before using this SDK. See the [deployment guide](https://docs.authorizer.dev/deployment) to spin one up.

## Install

```bash
pip install authorizer-py
```

For gRPC transport, install the optional extras:

```bash
pip install 'authorizer-py[grpc]'
```

## Initialize the client

| Parameter       | Required | Description                                                                                                                                                     |
| --------------- | -------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `client_id`     | Yes      | Your Authorizer app's client ID                                                                                                                                 |
| `authorizer_url`| Yes      | Base URL of your Authorizer instance (no trailing slash)                                                                                                        |
| `redirect_url`  | No       | Default redirect URL used by magic-link and forgot-password flows                                                                                               |
| `extra_headers` | No       | Additional headers sent on every request (e.g. custom `Origin`)                                                                                                 |
| `protocol`      | No       | Transport: `"graphql"` (default), `"rest"`, or `"grpc"`                                                                                                         |
| `grpc_endpoint` | No       | gRPC target `host:port`. The server's gRPC listener runs on a separate port (default `9091`), not the HTTP URL's port. Only used when `protocol="grpc"`.        |

### Protocol option

The `protocol` parameter selects which transport the SDK uses:

- `"graphql"` (default) — sends requests to the `/graphql` endpoint
- `"rest"` — uses the REST API (`/api/*`)
- `"grpc"` — uses the gRPC endpoint (requires `authorizer-py[grpc]` and the server running >= v2.3.0)

**Sync client:**

```python
from authorizer import AuthorizerClient

client = AuthorizerClient(
    client_id="YOUR_CLIENT_ID",
    authorizer_url="https://your-instance.authorizer.dev",
    # optional — 'graphql' (default), 'rest', or 'grpc'
    protocol="graphql",
)

# Use as a context manager to auto-close the HTTP session
with AuthorizerClient(
    client_id="YOUR_CLIENT_ID",
    authorizer_url="https://your-instance.authorizer.dev",
) as client:
    ...
```

**Async client:**

```python
from authorizer import AsyncAuthorizerClient

async with AsyncAuthorizerClient(
    client_id="YOUR_CLIENT_ID",
    authorizer_url="https://your-instance.authorizer.dev",
) as client:
    ...
```

## Usage

### Login

```python
from authorizer import AuthorizerClient, LoginRequest

with AuthorizerClient(
    client_id="YOUR_CLIENT_ID",
    authorizer_url="https://your-instance.authorizer.dev",
) as client:
    token = client.login(LoginRequest(email="user@example.com", password="Abc@123"))
    if token.user:
        print("Logged in as:", token.user.email)
    print("access_token:", token.access_token)
```

> **Note (Authorizer >= v2.3.0):** the server's CSRF guard requires an `Origin` header on state-changing requests. The client sends the Authorizer server's own origin by default, which always passes. If your instance restricts `ALLOWED_ORIGINS`, pass your app's origin instead via `extra_headers`: `{"Origin": "https://your-app.com"}`.

## gRPC transport

Set `protocol="grpc"` to call the server over gRPC. The server's gRPC listener runs on a separate port (default `9091`). When `grpc_endpoint` is unset, the host is taken from `authorizer_url` and port `9091` is used; pass `grpc_endpoint` to dial a custom target:

```python
from authorizer import AuthorizerClient

client = AuthorizerClient(
    client_id="YOUR_CLIENT_ID",
    authorizer_url="https://your-instance.authorizer.dev",
    protocol="grpc",
    grpc_endpoint="your-instance.authorizer.dev:9091",  # optional; defaults to host:9091
)
```

## Admin API

The SDK exposes admin methods for server-side use cases (user management, session listing, etc.). Admin methods require the admin secret, which you should pass via `extra_headers` or by using the admin client directly. See the [admin API docs](https://docs.authorizer.dev/core/admin-api) for the full list of operations.

## Fine-grained authorization (FGA)

Authorizer supports OpenFGA-style relationship-based access control. The subject of a permission check defaults to the authenticated caller — it is pinned server-side from the `Authorization` header you supply. The optional `user` field on `CheckPermissionsRequest` / `ListPermissionsRequest` is honored only for super-admins or when the value matches the caller's own identity.

```python
from authorizer import (
    AuthorizerClient,
    CheckPermissionsRequest,
    ListPermissionsRequest,
    PermissionCheckInput,
)

client = AuthorizerClient("YOUR_CLIENT_ID", "https://your-instance.authorizer.dev")
auth = {"Authorization": "Bearer USER_ACCESS_TOKEN"}

# Check multiple relations in one call
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

# List all objects the caller can view
accessible = client.list_permissions(
    ListPermissionsRequest(relation="can_view", object_type="document"),
    headers=auth,
)
print("can view:", accessible.objects)
client.close()
```

## License

Apache-2.0 — see [LICENSE](LICENSE) for details.

---

## Release

1. Bump the version in `setup.py` / `pyproject.toml`.
2. Tag the commit: `git tag v<version>`
3. Push with tags: `git push origin main --tags`

The GitHub Actions release workflow handles PyPI publish and GitHub Release creation automatically.
