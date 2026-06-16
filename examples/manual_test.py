"""Manual end-to-end smoke test for the Authorizer Python SDK.

Exercises the public client (meta/signup/login/profile) and the admin client
(users/webhooks/FGA) over the protocol you pick.

Setup + run (defaults shown):

    python -m venv .venv
    ./.venv/bin/pip install -e ".[grpc]"   # drop [grpc] if you only use graphql/rest

    AUTHORIZER_URL=http://localhost:8080 \
    CLIENT_ID=test-client \
    ADMIN_SECRET=admin \
    PROTOCOL=graphql \   # graphql | rest | grpc
    ./.venv/bin/python examples/manual_test.py

gRPC listens on its own port (default :9091); override with GRPC_ENDPOINT=host:port.
For plaintext gRPC the server must run with --grpc-insecure=true.
"""

from __future__ import annotations

import os
import time

from authorizer import (
    AddWebhookRequest,
    AuthorizerAdminClient,
    AuthorizerClient,
    FgaReadTuplesRequest,
    FgaTupleInput,
    FgaWriteModelRequest,
    FgaWriteTuplesRequest,
    LoginRequest,
    SignUpRequest,
    WebhookRequest,
)
from authorizer.exceptions import AuthorizerError

URL = os.getenv("AUTHORIZER_URL", "http://localhost:8080")
CLIENT_ID = os.getenv("CLIENT_ID", "test-client")
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "admin")
PROTOCOL = os.getenv("PROTOCOL", "graphql")  # graphql | rest | grpc
GRPC_ENDPOINT = os.getenv("GRPC_ENDPOINT", "")

FGA_MODEL = """model
  schema 1.1
type user
type document
  relations
    define viewer: [user]"""


def step(label: str, fn) -> None:
    """Run fn(), print result; never abort so the whole flow runs."""
    try:
        result = fn()
        print(f"✓ {label:<22} {result}")
    except AuthorizerError as exc:  # noqa: BLE001 - demo wants every call attempted
        print(f"✗ {label:<22} error: {exc}")
    except Exception as exc:  # noqa: BLE001
        print(f"✗ {label:<22} error: {exc}")


def main() -> None:
    print(f"== Authorizer Python SDK manual test ==\nurl={URL} protocol={PROTOCOL}\n")

    client = AuthorizerClient(
        client_id=CLIENT_ID,
        authorizer_url=URL,
        protocol=PROTOCOL,
        grpc_endpoint=GRPC_ENDPOINT,
    )

    step("get_meta_data", lambda: client.get_meta_data())

    email = f"py-manual-{time.time_ns()}@example.com"
    step(
        "signup",
        lambda: client.signup(
            SignUpRequest(email=email, password="Test@12345", confirm_password="Test@12345")
        ),
    )

    auth = None

    def _login():
        nonlocal auth
        auth = client.login(LoginRequest(email=email, password="Test@12345"))
        return f"access_token={'set' if auth.access_token else 'none'}"

    step("login", _login)

    if auth and auth.access_token:
        step(
            "get_profile",
            lambda: client.get_profile({"Authorization": f"Bearer {auth.access_token}"}),
        )

    # ---- Admin client (auth via x-authorizer-admin-secret) ----
    print("\n-- admin --")
    admin = AuthorizerAdminClient(
        authorizer_url=URL,
        admin_secret=ADMIN_SECRET,
        protocol=PROTOCOL,
        grpc_endpoint=GRPC_ENDPOINT,
    )

    step("users", lambda: f"{len(admin.users().users)} user(s)")

    webhook_endpoint = "https://example.com/webhook"
    step(
        "add_webhook",
        lambda: admin.add_webhook(
            AddWebhookRequest(
                event_name="user.login",
                endpoint=webhook_endpoint,
                enabled=True,
            )
        ),
    )

    def _list_and_clean():
        resp = admin.webhooks()
        # Clean up by endpoint: the server appends a "-<timestamp>" suffix to
        # event_name (not a stable key); endpoint is stored verbatim.
        deleted = 0
        for w in resp.webhooks:
            if w.endpoint == webhook_endpoint:
                admin.delete_webhook(WebhookRequest(id=w.id))
                deleted += 1
        return f"{len(resp.webhooks)} webhook(s); deleted {deleted}"

    step("webhooks + cleanup", _list_and_clean)

    # ---- FGA admin ----
    print("\n-- fga admin --")
    step("fga_write_model", lambda: admin.fga_write_model(FgaWriteModelRequest(dsl=FGA_MODEL)))
    fga_object = f"document:{time.time_ns()}"  # unique so re-runs don't collide
    step(
        "fga_write_tuples",
        lambda: admin.fga_write_tuples(
            FgaWriteTuplesRequest(
                tuples=[FgaTupleInput(user="user:alice", relation="viewer", object=fga_object)]
            )
        ),
    )
    step("fga_read_tuples", lambda: f"{len(admin.fga_read_tuples(FgaReadTuplesRequest()).tuples)} tuple(s)")

    print("\ndone.")


if __name__ == "__main__":
    main()
