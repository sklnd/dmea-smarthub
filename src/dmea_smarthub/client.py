"""HTTP client and auth for the DMEA SmartHub co-op portal."""

from typing import Any, Self

import httpx2
from pydantic import BaseModel, ConfigDict
from pydantic.alias_generators import to_camel

DEFAULT_BASE_URL = "https://dmea.smarthub.coop"
DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


class AuthError(Exception):
    """Login failed or no token was issued."""


class CamelModel(BaseModel):
    """Validates SmartHub's camelCase JSON, exposes snake_case fields."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class AuthResponse(CamelModel):
    status: str
    authorization_token: str = ""
    username: str = ""
    expiration: int = 0
    expires_in: int = 0
    primary_username: str | None = None
    is_secondary_registration: bool = False
    is_business_user: bool = False


class SmartHub:
    """Async SmartHub client.

    Usage:
        async with SmartHub() as hub:
            auth = await hub.login(user_id, password)
    """

    AUTH_PATH = "/services/oauth/auth/v2"

    def __init__(self, base_url: str = DEFAULT_BASE_URL, **kwargs: Any):
        self._http = httpx2.AsyncClient(
            base_url=base_url,
            headers={"User-Agent": DEFAULT_USER_AGENT},
            **kwargs,
        )
        self.auth: AuthResponse | None = None

    async def login(self, user_id: str, password: str) -> AuthResponse:
        """POST credentials, store the issued JWT, attach it to future requests."""
        resp = await self._http.post(
            self.AUTH_PATH,
            data={"userId": user_id, "password": password},
        )
        resp.raise_for_status()
        auth = AuthResponse.model_validate(resp.json())
        if auth.status != "SUCCESS" or not auth.authorization_token:
            raise AuthError(f"login failed (status={auth.status!r})")
        self.auth = auth
        # ponytail: header name unverified; confirm against devtools captures of usage endpoints
        self._http.headers["authorizationToken"] = auth.authorization_token
        return auth

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
