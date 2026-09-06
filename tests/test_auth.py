import asyncio
import urllib.parse

import httpx2
import pytest

from dmea_smarthub import AuthError, AuthInfo, SmartHub

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1QGV4YW1wbGUuY29tIn0.sig"

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


def handler(request: httpx2.Request) -> httpx2.Response:
    assert request.url.path == "/services/oauth/auth/v2"
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    form = urllib.parse.parse_qs(request.content.decode())
    if form["password"] == ["good"]:
        return httpx2.Response(200, json=RESP)
    return httpx2.Response(
        200, json={"status": "INVALID_CREDENTIALS", "authorizationToken": ""}
    )


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
            assert hub._http.headers["authorizationToken"] == JWT

    asyncio.run(run())


def test_login_failure(hub: SmartHub):
    async def run():
        async with hub:
            with pytest.raises(AuthError):
                await hub.login(AuthInfo(user_id="u@example.com", password="bad"))

    asyncio.run(run())
