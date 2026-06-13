"""Minimal synchronous usage example."""

from authorizer import AuthorizerClient, LoginRequest

client = AuthorizerClient(
    client_id="YOUR_CLIENT_ID",
    authorizer_url="https://your-instance.authorizer.dev",
)

token = client.login(LoginRequest(email="test@yopmail.com", password="Abc@123"))
print("access_token:", token.access_token)
client.close()
