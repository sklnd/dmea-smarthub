import asyncio
import base64
import json
import time
from datetime import UTC, datetime

import httpx2
import pytest

from dmea_smarthub import (
    Aggregation,
    AuthError,
    AuthResponse,
    SmartHub,
    TimeRange,
    UsageError,
)

# fixed "now"; TOKEN stays valid at this instant, JWT2 is for after travel
FROZEN = time.time()


def make_jwt(exp_offset: float) -> str:
    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none'})}.{b64({'exp': FROZEN + exp_offset})}.sig"


TOKEN = make_jwt(3600)
JWT2 = make_jwt(7200)

RESP = {
    "status": "SUCCESS",
    "authorizationToken": TOKEN,
    "username": "u@example.com",
}

ACCOUNTS = [{"account": "1708290003", "serviceLocations": ["17082900"]}]

USAGE_BODY = {
    "type": "USAGE",
    "meters": [
        {"flowDirection": "FORWARD", "seriesId": "fwd"},
    ],
    "series": [
        {
            "name": "fwd",
            "data": [
                {"x": 1788242400000, "y": 1.5},
                {"x": 1788246000000, "y": 2.0},
            ],
        },
    ],
}

NET_BODY = {
    "type": "USAGE",
    "meters": [{"flowDirection": "NET", "seriesId": "net1"}],
    "series": [
        {"name": "fwd", "data": [{"x": 1788242400000, "y": 9.9}]},
        {"name": "net1", "data": [{"x": 1788242400000, "y": 0.25}]},
    ],
}

START = datetime(2026, 9, 1, tzinfo=UTC)
END = datetime(2026, 9, 2, tzinfo=UTC)
RANGE = TimeRange(start=START, end=END)

state: dict = {
    "polls": 0,
    "payloads": [],
    "bearer": [],
    "always_pending": False,
    "net": False,
    "weird_status": False,
}


def handler(request: httpx2.Request) -> httpx2.Response:
    bearer: list[str] = state["bearer"]
    payloads: list[dict] = state["payloads"]
    if request.url.path == "/services/oauth/auth/v2":
        return httpx2.Response(200, json=RESP)
    if request.url.path == "/services/oauth/auth/v2/refresh":
        return httpx2.Response(200, json={**RESP, "authorizationToken": JWT2})
    if request.url.path == "/services/secured/accounts":
        assert request.headers["authorization"].startswith("Bearer ")
        bearer.append(request.headers["authorization"].removeprefix("Bearer "))
        return httpx2.Response(200, json=ACCOUNTS)
    assert request.url.path == "/services/secured/utility-usage/poll"
    assert request.headers["content-type"] == "application/json"
    assert request.headers["authorization"].startswith("Bearer ")
    bearer.append(request.headers["authorization"].removeprefix("Bearer "))
    payloads.append(json.loads(request.content))
    state["polls"] += 1
    if state["weird_status"]:
        return httpx2.Response(200, json={"status": "WEIRD"})
    if state["always_pending"]:
        return httpx2.Response(200, json={"status": "PENDING"})
    if state["net"]:
        body = {"status": "COMPLETE", "data": {"ELECTRIC": [NET_BODY]}}
    elif state["polls"] < 2:
        return httpx2.Response(200, json={"status": "PENDING"})
    else:
        body = {"status": "COMPLETE", "data": {"ELECTRIC": [USAGE_BODY]}}
    return httpx2.Response(200, json=body)


@pytest.fixture(autouse=True)
def reset_state(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(SmartHub, "POLL_DELAY", 0)
    state.update(
        polls=0,
        payloads=[],
        bearer=[],
        always_pending=False,
        net=False,
        weird_status=False,
    )


def make_client() -> httpx2.AsyncClient:
    """Pre-built mock client for injection via SmartHub(http=...)."""
    return httpx2.AsyncClient(
        base_url="https://dmea.smarthub.coop", transport=httpx2.MockTransport(handler)
    )


def make_hub(**kwargs) -> SmartHub:
    auth = AuthResponse(
        status="SUCCESS", authorization_token=TOKEN, username="u@example.com"
    )
    return SmartHub(
        http=make_client(),
        auth=auth,
        **kwargs,
    )


def test_get_usage_polls_until_complete(travel_to_frozen):
    async def run():
        async with make_hub() as hub:
            return await hub.get_usage("17082900", RANGE, Aggregation.HOURLY)

    usage = asyncio.run(run())
    assert usage.status == "COMPLETE"
    assert state["polls"] == 2
    assert state["payloads"][0] == {
        "timeFrame": "HOURLY",
        "userId": "u@example.com",
        "screen": "USAGE_EXPLORER",
        "includeDemand": False,
        "serviceLocationNumber": "17082900",
        "accountNumber": "1708290003",
        "industries": ["ELECTRIC"],
        "startDateTime": int(START.timestamp() * 1000),
        "endDateTime": int(END.timestamp() * 1000),
        "selectedIndustry": "ELECTRIC",
    }
    series = usage.usage_series
    assert series is not None and series.name == "fwd"
    assert [p.value for p in series.data] == [1.5, 2.0]
    assert series.data[0].timestamp == datetime.fromtimestamp(
        1788242400000 / 1000, tz=UTC
    )


def test_get_usage_explicit_account_skips_lookup(travel_to_frozen):
    async def run():
        async with make_hub() as hub:
            return await hub.get_usage("17082900", RANGE, account="1708290003")

    asyncio.run(run())
    assert state["payloads"][0]["accountNumber"] == "1708290003"


def test_usage_series_prefers_net(travel_to_frozen):
    state["net"] = True

    async def run():
        async with make_hub() as hub:
            return await hub.get_usage("17082900", RANGE, account="1708290003")

    usage = asyncio.run(run())
    series = usage.usage_series
    assert series is not None
    assert series.name == "net1"
    assert [p.value for p in series.data] == [0.25]


def test_usage_pending_exhaustion(monkeypatch: pytest.MonkeyPatch, travel_to_frozen):
    monkeypatch.setattr(SmartHub, "POLL_ATTEMPTS", 3)
    state["always_pending"] = True

    async def run():
        async with make_hub() as hub:
            await hub.get_usage("17082900", RANGE, account="1708290003")

    with pytest.raises(UsageError):
        asyncio.run(run())


def test_get_usage_reauths_on_401(travel_to_frozen):
    client = make_client()
    original_send = client.send

    async def flaky_send(request, **kw):
        if (
            request.url.path == "/services/secured/utility-usage/poll"
            and not state["bearer"]
        ):
            state["bearer"].append("")
            return httpx2.Response(401)
        return await original_send(request, **kw)

    client.send = flaky_send  # ty: ignore[invalid-assignment]

    async def run():
        async with SmartHub(
            http=client,
            auth=AuthResponse(
                status="SUCCESS", authorization_token=TOKEN, username="u@example.com"
            ),
        ) as hub:
            return await hub.get_usage("17082900", RANGE, account="1708290003")

    usage = asyncio.run(run())
    assert usage.status == "COMPLETE"
    # "" = the 401; retry after re-auth used the refreshed token
    assert state["bearer"][0] == ""
    assert all(b == JWT2 for b in state["bearer"][1:])


def test_get_usage_without_auth_or_credentials():
    async def run():
        async with SmartHub(http=make_client()) as hub:
            await hub.get_usage("17082900", RANGE)

    with pytest.raises(AuthError):
        asyncio.run(run())


def test_time_range_ms():
    assert RANGE.start_ms == 1788220800000
    assert RANGE.end_ms == 1788307200000


def test_unknown_status_rejected_as_usage_error(travel_to_frozen):
    """A status outside the union surfaces as UsageError, not ValidationError."""
    state["weird_status"] = True

    async def run():
        async with make_hub() as hub:
            await hub.get_usage("17082900", RANGE, account="1708290003")

    with pytest.raises(UsageError, match="WEIRD"):
        asyncio.run(run())
