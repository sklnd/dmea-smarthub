"""Shared keychain + client helpers for CLI commands."""

import keyring
import typer

from dmea_smarthub import AuthInfo, AuthResponse, SmartHub

SERVICE = "dmea-smarthub"


def load_client() -> SmartHub:
    """Build a SmartHub client from saved keychain credentials + token."""
    user_id = keyring.get_password(SERVICE, "user_id")
    password = keyring.get_password(SERVICE, "password")
    token = keyring.get_password(SERVICE, "token")
    if not user_id or not password:
        typer.echo("no saved credentials; run 'auth login' first", err=True)
        raise typer.Exit(1)
    auth = None
    if token:
        auth = AuthResponse(
            status="SUCCESS", authorization_token=token, username=user_id
        )
    return SmartHub(auth=auth, auth_info=AuthInfo(user_id=user_id, password=password))


def save_token(hub: SmartHub) -> None:
    """Persist the client's (possibly refreshed) token back to the keychain."""
    if hub.auth and hub.auth.authorization_token:
        keyring.set_password(SERVICE, "token", hub.auth.authorization_token)
