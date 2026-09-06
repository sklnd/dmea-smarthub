import asyncio
import base64
import json
import time
import urllib.parse

import httpx2
import pytest

from dmea_smarthub import Account, AuthError, AuthInfo, AuthResponse, SmartHub

# fixed "now" the mock tokens are minted against; see travel_to_frozen fixture
FROZEN = time.time()


def make_jwt(exp_offset: float) -> str:
    """Craft an unsigned JWT with an exp claim exp_offset seconds from FROZEN."""

    def b64(obj: dict) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

    return f"{b64({'alg': 'none'})}.{b64({'exp': FROZEN + exp_offset})}.sig"


# tokens the mock auth endpoints issue: fresh (future exp) and refreshed
JWT = make_jwt(3600)
JWT2 = make_jwt(3600)
OLD_TOKEN = "old-token"

RESP = {
    "status": "SUCCESS",
    "authorizationToken": JWT,
    "username": "u@example.com",
    "expiration": 1788727614,
    "primaryUsername": "u@example.com",
    "isSecondaryRegistration": False,
    "expiresIn": 299,
    "isBusinessUser": False,
}

ACCOUNTS = [
    {"account": "1706049004", "serviceLocations": ["17060490"]},
    {"account": "1708290003", "serviceLocations": ["17082900"]},
]

state: dict = {"seen": []}


def handler(request: httpx2.Request) -> httpx2.Response:
    form = urllib.parse.parse_qs(request.content.decode())
    if request.url.path == "/services/oauth/auth/v2":
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"
        if form["password"] == ["good"]:
            return httpx2.Response(200, json=RESP)
        return httpx2.Response(
            200, json={"status": "INVALID_CREDENTIALS", "authorizationToken": ""}
        )
    if request.url.path == "/services/oauth/auth/v2/refresh":
        if state.get("refresh_fails"):
            return httpx2.Response(500, text="boom")
        if state.get("refresh_junk"):
            return httpx2.Response(200, json={"isBusinessUser": False})
        if form["token"] == ["bogus"]:
            return httpx2.Response(
                200, json={"status": "INVALID_TOKEN", "authorizationToken": ""}
            )
        return httpx2.Response(200, json={**RESP, "authorizationToken": JWT2})
    assert request.url.path == "/services/secured/accounts"
    assert request.headers["authorization"].startswith("Bearer ")
    state["seen"].append(request.headers["authorization"].removeprefix("Bearer "))
    assert request.url.params["user"] == "u@example.com"
    return httpx2.Response(200, json=ACCOUNTS)


@pytest.fixture(autouse=True)
def reset_state():
    state["seen"] = []
    state.pop("refresh_fails", None)
    state.pop("refresh_junk", None)


@pytest.fixture
def hub() -> SmartHub:
    return SmartHub(transport=httpx2.MockTransport(handler))


def test_login_success(hub: SmartHub):
    async def run():
        async with hub:
            auth = await hub.login(AuthInfo(user_id="u@example.com", password="good"))
            assert auth.authorization_token == JWT
            assert auth.username == "u@example.com"
            assert auth.expires_in == 299
            assert auth.is_business_user is False
            assert hub._http.headers["authorization"] == f"Bearer {JWT}"

    asyncio.run(run())


def test_login_failure(hub: SmartHub):
    async def run():
        async with hub:
            with pytest.raises(AuthError):
                await hub.login(AuthInfo(user_id="u@example.com", password="bad"))

    asyncio.run(run())


def test_refresh_success(hub: SmartHub):
    async def run():
        async with hub:
            auth = await hub.refresh(OLD_TOKEN)
            assert auth.authorization_token == JWT2
            assert auth.status == "SUCCESS"
            assert hub._http.headers["authorization"] == f"Bearer {JWT2}"

    asyncio.run(run())


def test_refresh_failure(hub: SmartHub):
    async def run():
        async with hub:
            with pytest.raises(AuthError):
                await hub.refresh("bogus")

    asyncio.run(run())


def test_list_accounts_with_valid_token(travel_to_frozen):
    auth = AuthResponse(
        status="SUCCESS",
        authorization_token=make_jwt(3600),
        username="u@example.com",
    )

    async def run():
        accounts = await SmartHub(
            transport=httpx2.MockTransport(handler), auth=auth
        ).list_accounts()
        assert state["seen"] == [auth.authorization_token]
        assert [a.account for a in accounts] == ["1706049004", "1708290003"]
        assert accounts[0].service_locations == ["17060490"]

    asyncio.run(run())


def test_list_accounts_refreshes_expired_token(travel_to_frozen):
    async def run():
        auth = AuthResponse(
            status="SUCCESS",
            authorization_token=make_jwt(-3600),
            username="u@example.com",
        )
        async with SmartHub(transport=httpx2.MockTransport(handler), auth=auth) as hub:
            accounts = await hub.list_accounts()
            assert hub.auth is not None
            assert hub.auth.authorization_token == JWT2
            assert state["seen"] == [JWT2]
            assert len(accounts) == 2

    asyncio.run(run())


def test_list_accounts_relogins_when_refresh_fails(travel_to_frozen):
    async def run():
        auth = AuthResponse(
            status="SUCCESS",
            authorization_token="bogus",
            username="u@example.com",
        )
        async with SmartHub(
            transport=httpx2.MockTransport(handler),
            auth=auth,
            auth_info=AuthInfo(user_id="u@example.com", password="good"),
        ) as hub:
            accounts = await hub.list_accounts()
            assert hub.auth is not None
            assert hub.auth.authorization_token == JWT
            assert state["seen"] == [JWT]
            assert len(accounts) == 2

    asyncio.run(run())


def test_list_accounts_no_auth_no_credentials(travel_to_frozen):
    async def run():
        async with SmartHub(transport=httpx2.MockTransport(handler)) as fresh:
            with pytest.raises(AuthError):
                await fresh.list_accounts()

    asyncio.run(run())


def test_account_model():
    acct = Account.model_validate(ACCOUNTS[0])
    assert acct.account == "1706049004"
    assert acct.service_locations == ["17060490"]


def test_refresh_500_falls_back_to_relogin(travel_to_frozen):
    """A 500 (or junk body) on refresh must trigger re-login, not leak errors."""
    state["refresh_fails"] = True

    async def run():
        auth = AuthResponse(
            status="SUCCESS",
            authorization_token=make_jwt(-3600),
            username="u@example.com",
        )
        async with SmartHub(
            transport=httpx2.MockTransport(handler),
            auth=auth,
            auth_info=AuthInfo(user_id="u@example.com", password="good"),
        ) as hub:
            accounts = await hub.list_accounts()
            assert hub.auth is not None
            assert hub.auth.authorization_token == JWT
            assert state["seen"] == [JWT]
            assert len(accounts) == 2

    asyncio.run(run())


def test_refresh_junk_body_falls_back_to_relogin(travel_to_frozen):
    state["refresh_junk"] = True

    async def run():
        auth = AuthResponse(
            status="SUCCESS",
            authorization_token=make_jwt(-3600),
            username="u@example.com",
        )
        async with SmartHub(
            transport=httpx2.MockTransport(handler),
            auth=auth,
            auth_info=AuthInfo(user_id="u@example.com", password="good"),
        ) as hub:
            await hub.list_accounts()
            assert hub.auth is not None
            assert hub.auth.authorization_token == JWT

    asyncio.run(run())


def test_refresh_failure_without_credentials(travel_to_frozen):
    state["refresh_junk"] = True

    async def run():
        auth = AuthResponse(
            status="SUCCESS",
            authorization_token=make_jwt(-3600),
            username="u@example.com",
        )
        async with SmartHub(transport=httpx2.MockTransport(handler), auth=auth) as hub:
            await hub.list_accounts()

    with pytest.raises(AuthError, match="re-authentication required"):
        asyncio.run(run())
