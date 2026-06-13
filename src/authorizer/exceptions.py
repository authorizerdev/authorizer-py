"""Exception types raised by the Authorizer SDK."""

from __future__ import annotations


class AuthorizerError(Exception):
    """Raised when an Authorizer API call fails.

    Attributes:
        message: human-readable error message.
        errors: underlying error messages (e.g. GraphQL ``errors`` array).
        status: HTTP status code when available.
    """

    def __init__(
        self,
        message: str,
        *,
        errors: list[object] | None = None,
        status: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.errors: list[object] = list(errors) if errors else []
        self.status = status


class AuthorizerConnectionError(AuthorizerError):
    """Raised when the request never reached the server (network/transport error)."""
