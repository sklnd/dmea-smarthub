"""HTTP client and auth for the DMEA SmartHub co-op portal."""

import base64
import json
import logging
import time
from typing import Any, Self

import httpx2
from pydantic import BaseModel, ConfigDict, SecretStr
from pydantic.alias_generators import to_camel

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://dmea.smarthub.coop"
DEFAULT_USER_AGENT = "dmea-smarthub/0.1"
DEFAULT_HEADERS = {
    "User-Agent": DEFAULT_USER_AGENT,
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
    "Origin": "https://dmea.smarthub.coop",
    "Referer": "https://dmea.smarthub.coop/ui/",
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}


class AuthError(Exception):
    """Login failed or no token was issued."""


class CamelModel(BaseModel):
    """Validates SmartHub's camelCase JSON, exposes snake_case fields."""

    model_config = ConfigDict(alias_generator=to_camel, populate_by_name=True)


class AuthInfo(BaseModel):
    """Credentials for SmartHub login."""

    user_id: str
    password: SecretStr


class AuthResponse(CamelModel):
    status: str
    authorization_token: str = ""
    username: str = ""
    expiration: int = 0
    expires_in: int = 0
    primary_username: str | None = None
    is_secondary_registration: bool = False
    is_business_user: bool = False


class Account(CamelModel):
    account: str
    service_locations: list[str] = []


class SmartHub:
    """Async SmartHub client.

    Usage:
        async with SmartHub() as hub:
            auth = await hub.login(AuthInfo(user_id=..., password=...))
    """

    AUTH_PATH = "/services/oauth/auth/v2"
    REFRESH_PATH = "/services/oauth/auth/v2/refresh"
    ACCOUNTS_PATH = "/services/secured/accounts"

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        auth: AuthResponse | None = None,
        auth_info: AuthInfo | None = None,
        **kwargs: Any,
    ):
        self._http = httpx2.AsyncClient(
            base_url=base_url,
            headers={**DEFAULT_HEADERS, **kwargs.pop("headers", {})},
            **kwargs,
        )
        self.auth: AuthResponse | None = None
        self._auth_info: AuthInfo | None = None
        if auth and auth.authorization_token:
            self._store(auth)
        if auth_info:
            self._auth_info = auth_info

    async def login(self, auth_info: AuthInfo) -> AuthResponse:
        """POST credentials, store the issued JWT, attach it to future requests."""
        req = self._http.build_request(
            "POST",
            self.AUTH_PATH,
            data={
                "userId": auth_info.user_id,
                "password": auth_info.password.get_secret_value(),
            },
        )
        logger.debug("route: POST %s", req.url)
        logger.debug("request headers=%s", dict(req.headers))
        logger.debug("request body: userId=%s password=***", auth_info.user_id)
        resp = await self._http.send(req)
        logger.debug("response %s: %s", resp.status_code, resp.text)
        resp.raise_for_status()
        auth = AuthResponse.model_validate(resp.json())
        if auth.status != "SUCCESS" or not auth.authorization_token:
            raise AuthError(f"login failed (status={auth.status!r})")
        self._store(auth)
        return auth

    async def refresh(self, token: str) -> AuthResponse:
        """POST a token, store the refreshed JWT returned."""
        req = self._http.build_request(
            "POST",
            self.REFRESH_PATH,
            data={"token": token},
        )
        logger.debug("route: POST %s", req.url)
        logger.debug("request headers=%s", dict(req.headers))
        logger.debug("request body: token=%s...", token[:12])
        resp = await self._http.send(req)
        logger.debug("response %s: %s", resp.status_code, resp.text)
        resp.raise_for_status()
        auth = AuthResponse.model_validate(resp.json())
        if auth.status != "SUCCESS" or not auth.authorization_token:
            raise AuthError(f"refresh failed (status={auth.status!r})")
        self._store(auth)
        return auth

    def _store(self, auth: AuthResponse) -> None:
        self.auth = auth
        if auth.authorization_token:
            self._http.headers["Authorization"] = f"Bearer {auth.authorization_token}"

    async def list_accounts(self, user: str | None = None) -> list[Account]:
        """List the accounts on the user's SmartHub profile."""
        await self._ensure_auth()

        if self.auth is None or not self.auth.username:
            raise AuthError("cannot determine user for accounts lookup")

        req = self._http.build_request(
            "GET",
            self.ACCOUNTS_PATH,
            params={"user": user or self.auth.username},
        )
        logger.debug("route: GET %s", req.url)
        logger.debug("request headers=%s", dict(req.headers))
        resp = await self._http.send(req)
        logger.debug("response %s: %s", resp.status_code, resp.text)
        resp.raise_for_status()
        return [Account.model_validate(item) for item in resp.json()]

    async def _ensure_auth(self) -> None:
        """Make sure we hold a live token: refresh it or re-login if expired."""
        if self.auth is None or not self.auth.authorization_token:
            if self._auth_info is None:
                raise AuthError("not authenticated; login required")
            logger.debug("no token; logging in")
            await self.login(self._auth_info)
            return
        token = self.auth.authorization_token
        if not self._jwt_expired(token):
            return
        logger.debug("token expired; refreshing")
        try:
            await self.refresh(token)
        except AuthError:
            if self._auth_info is None:
                raise AuthError("token expired; re-authentication required") from None
            logger.debug("refresh failed; re-authenticating")
            await self.login(self._auth_info)

    @staticmethod
    def _jwt_expired(token: str) -> bool:
        """True if the JWT's exp claim is missing or within 30s of passing."""
        try:
            payload_b64 = token.split(".")[1]
            payload = json.loads(base64.urlsafe_b64decode(payload_b64 + "=="))
            exp: float | None = payload.get("exp")
        except IndexError, ValueError, TypeError, json.JSONDecodeError:
            return True
        return exp is None or exp <= time.time() + 30

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.aclose()
