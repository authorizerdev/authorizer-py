"""Minimal asynchronous usage example."""

import asyncio

from authorizer import AsyncAuthorizerClient, LoginRequest


async def main() -> None:
    async with AsyncAuthorizerClient(
        client_id="YOUR_CLIENT_ID",
        authorizer_url="https://your-instance.authorizer.dev",
    ) as client:
        token = await client.login(LoginRequest(email="test@yopmail.com", password="Abc@123"))
        print("access_token:", token.access_token)


asyncio.run(main())
