"""HTTP client and auth for the DMEA SmartHub co-op portal."""

import asyncio
import base64
import json
import logging
import time
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, Any, Literal, Self

import httpx2
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretStr,
    TypeAdapter,
    ValidationError,
    model_validator,
)
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


class UsageError(Exception):
    """Usage data could not be fetched or parsed."""


class Aggregation(StrEnum):
    HOURLY = "HOURLY"
    DAILY = "DAILY"
    MONTHLY = "MONTHLY"


class TimeRange(BaseModel):
    """Half-open time range; naive datetimes are interpreted in the local timezone."""

    start: datetime
    end: datetime

    @property
    def start_ms(self) -> int:
        return int(self.start.timestamp() * 1000)

    @property
    def end_ms(self) -> int:
        return int(self.end.timestamp() * 1000)


class UsagePoint(BaseModel):
    """One reading: epoch-ms timestamp + value, wire keys x/y."""

    timestamp: datetime
    value: float

    @model_validator(mode="before")
    @classmethod
    def _from_xy(cls, data: Any) -> Any:
        if isinstance(data, dict) and "x" in data:
            return {
                "timestamp": datetime.fromtimestamp(data["x"] / 1000, tz=UTC),
                "value": data["y"],
            }
        return data


class UsageMeter(CamelModel):
    series_id: str
    flow_direction: Literal["FORWARD", "NET", "TOTAL"]


class UsageSeries(CamelModel):
    name: str
    data: list[UsagePoint] = []


class UsageEntry(CamelModel):
    type: str
    meters: list[UsageMeter] = []
    series: list[UsageSeries] = []


class UsageData(CamelModel):
    """The `data` object; keyed by industry, ELECTRIC is the one we model."""

    model_config = ConfigDict(extra="allow")

    electric: Annotated[list[UsageEntry], Field(alias="ELECTRIC")] = []


class UsagePending(CamelModel):
    """Poll response while the server is still computing the data."""

    status: Literal["PENDING"]


class UsageComplete(CamelModel):
    """Poll response with the usage payload attached."""

    status: Literal["COMPLETE"]
    data: UsageData

    @property
    def usage_series(self) -> UsageSeries | None:
        """The primary usage series: NET if the site is net-metered, else FORWARD."""
        for entry in self.data.electric:
            if entry.type != "USAGE":
                continue

            forward = net = ""
            for meter in entry.meters:
                match meter.flow_direction:
                    case "NET":
                        net = meter.series_id
                    case "FORWARD" | "TOTAL":
                        forward = meter.series_id

            wanted = net or forward
            return next(
                (series for series in entry.series if series.name == wanted), None
            )
        return None


UsageResponse = Annotated[UsagePending | UsageComplete, Field(discriminator="status")]
"""Discriminated poll response union, keyed on `status`."""

USAGE_RESPONSE_ADAPTER: TypeAdapter[UsagePending | UsageComplete] = TypeAdapter(
    UsageResponse
)


class SmartHub:
    """Async SmartHub client.

    Usage:
        async with SmartHub() as hub:
            auth = await hub.login(AuthInfo(user_id=..., password=...))
    """

    AUTH_PATH = "/services/oauth/auth/v2"
    REFRESH_PATH = "/services/oauth/auth/v2/refresh"
    ACCOUNTS_PATH = "/services/secured/accounts"
    USAGE_PATH = "/services/secured/utility-usage/poll"
    # ponytail: fixed 2s × 15 poll attempts (30s ceiling); raise if big windows stay PENDING longer
    POLL_DELAY = 2.0
    POLL_ATTEMPTS = 15

    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        auth: AuthResponse | None = None,
        auth_info: AuthInfo | None = None,
        http: httpx2.AsyncClient | None = None,
        **kwargs: Any,
    ):
        """Create a SmartHub client.

        Args:
            base_url: SmartHub portal root for the co-op, e.g.
                ``https://dmea.smarthub.coop``. Ignored when ``http`` is given.
            auth: Previously obtained auth response whose token is used for
                Bearer auth; skipped when absent. Expired tokens are
                refreshed or re-authenticated automatically on secured
                routes when ``auth_info`` is also provided.
            auth_info: Login credentials, used to (re-)authenticate when no
                token is held, the token is expired, or refresh fails.
            http: Existing ``httpx2.AsyncClient`` to use instead of creating
                one. Intended for unit testing (e.g. a MockTransport
                client); its ``base_url`` and headers take precedence.
            **kwargs: Remaining keyword arguments are forwarded to the
                internally created ``httpx2.AsyncClient`` (e.g.
                ``transport``, ``timeout``); ``headers`` is merged on top of
                the library defaults. Ignored when ``http`` is given.
        """
        self._http = http or httpx2.AsyncClient(
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
        auth = self._parse_auth(resp)
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
        auth = self._parse_auth(resp)
        if auth.status != "SUCCESS" or not auth.authorization_token:
            raise AuthError(f"refresh failed (status={auth.status!r})")
        self._store(auth)
        return auth

    @staticmethod
    def _parse_auth(resp: httpx2.Response) -> AuthResponse:
        """Validate an auth response body, surfacing junk payloads as AuthError."""
        try:
            return AuthResponse.model_validate(resp.json())
        except ValidationError as exc:
            raise AuthError(
                f"unexpected auth response ({resp.status_code}): {resp.text[:120]!r}"
            ) from exc

    def _store(self, auth: AuthResponse) -> None:
        self.auth = auth
        if auth.authorization_token:
            self._http.headers["Authorization"] = f"Bearer {auth.authorization_token}"
        if auth.username:
            self._http.headers["X-Nisc-Smarthub-Username"] = auth.username

    async def list_accounts(self, user: str | None = None) -> list[Account]:
        """List the accounts on the user's SmartHub profile."""
        if user is None:
            await self._ensure_auth()
            if self.auth is None or not self.auth.username:
                raise AuthError("cannot determine user for accounts lookup")
            user = self.auth.username
        resp = await self._send_secured(
            "GET", self.ACCOUNTS_PATH, params={"user": user}
        )
        return [Account.model_validate(item) for item in resp.json()]

    async def get_usage(
        self,
        location: str,
        time_range: TimeRange,
        aggregation: Aggregation = Aggregation.HOURLY,
        account: str | None = None,
        include_demand: bool = False,
    ) -> UsageComplete:
        """Fetch usage for a service location; polls until COMPLETE."""
        await self._ensure_auth()
        if self.auth is None or not self.auth.username:
            raise AuthError("cannot determine user for usage lookup")
        if account is None:
            account = await self._account_for_location(location)
        payload = {
            "timeFrame": aggregation.value,
            "userId": self.auth.username,
            "screen": "USAGE_EXPLORER",
            "includeDemand": include_demand,
            "serviceLocationNumber": location,
            "accountNumber": account,
            "industries": ["ELECTRIC"],
            "startDateTime": time_range.start_ms,
            "endDateTime": time_range.end_ms,
            "selectedIndustry": "ELECTRIC",
        }
        logger.debug("usage request payload: %s", payload)
        usage: UsagePending | UsageComplete | None = None
        last_status = "PENDING"
        for attempt in range(1, self.POLL_ATTEMPTS + 1):
            resp = await self._send_secured("POST", self.USAGE_PATH, json=payload)
            try:
                usage = USAGE_RESPONSE_ADAPTER.validate_python(resp.json())
            except ValidationError as exc:
                raise UsageError(
                    f"unexpected usage response ({resp.status_code}): {resp.text[:120]!r}"
                ) from exc
            if isinstance(usage, UsageComplete):
                return usage
            last_status = usage.status
            logger.debug("poll attempt %d: %s", attempt, last_status)
            await asyncio.sleep(self.POLL_DELAY)
        raise UsageError(
            f"usage data still {last_status!r} after {self.POLL_ATTEMPTS} attempts"
        )

    async def _account_for_location(self, location: str) -> str:
        """Derive the account number for a service location via /accounts."""
        for acct in await self.list_accounts():
            if location in acct.service_locations:
                return acct.account
        raise UsageError(f"no account found for service location {location}")

    async def _send_secured(
        self, method: str, path: str, **kwargs: Any
    ) -> httpx2.Response:
        """Send an authenticated request; re-auth and retry once on 401."""
        await self._ensure_auth()
        resp = await self._http.send(self._http.build_request(method, path, **kwargs))
        logger.debug("route: %s %s -> %s", method, path, resp.status_code)
        is_json = "json" in resp.headers.get("content-type", "")
        logger.debug(
            "response body: %s",
            json.dumps(resp.json(), indent=2) if is_json else resp.text,
        )
        if resp.status_code == 401:
            logger.debug("401; forcing re-auth and retrying once")
            await self._ensure_auth(force=True)
            resp = await self._http.send(
                self._http.build_request(method, path, **kwargs)
            )
            logger.debug("route: %s %s -> %s (retry)", method, path, resp.status_code)
        resp.raise_for_status()
        return resp

    async def _ensure_auth(self, force: bool = False) -> None:
        """Make sure we hold a live token: refresh it or re-login if expired."""
        token = self.auth.authorization_token if self.auth else ""
        if token and not force and not self._jwt_expired(token):
            return
        if token:
            logger.debug("token expired; refreshing")
            try:
                await self.refresh(token)
                return
            except AuthError, httpx2.HTTPError:
                if self._auth_info is None:
                    raise AuthError(
                        "token expired; re-authentication required"
                    ) from None
                logger.debug("refresh failed; re-authenticating")
        if self._auth_info is None:
            raise AuthError("not authenticated; login required")
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
