"""Auth subcommands for the DMEA SmartHub CLI."""

import asyncio

import httpx2
import keyring
import keyring.errors
import typer

from dmea_smarthub import AuthError, AuthInfo, SmartHub

auth_app = typer.Typer(no_args_is_help=True)

SERVICE = "dmea-smarthub"


@auth_app.command()
def login(
    user_id: str = typer.Option(None, "--user-id", help="Defaults to saved user."),
    password: str = typer.Option(
        None, "--password", help="Defaults to saved password.", hide_input=True
    ),
) -> None:
    """Authenticate, print the auth response, and save credentials to the keychain."""
    user_id = user_id or keyring.get_password(SERVICE, "user_id") or ""
    password = password or keyring.get_password(SERVICE, "password") or ""
    if not user_id:
        user_id = typer.prompt("User ID")
    if not password:
        password = typer.prompt("Password", hide_input=True)

    async def run() -> None:
        async with SmartHub() as hub:
            auth = await hub.login(AuthInfo(user_id=user_id, password=password))
        keyring.set_password(SERVICE, "user_id", user_id)
        keyring.set_password(SERVICE, "password", password)
        keyring.set_password(SERVICE, "token", auth.authorization_token)
        typer.echo("Success. Saved credentials and token to keychain")

    try:
        asyncio.run(run())
    except AuthError as exc:
        typer.echo(f"login failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    except httpx2.HTTPError as exc:
        typer.echo(f"request failed: {exc}", err=True)
        raise typer.Exit(1) from exc


@auth_app.command()
def refresh() -> None:
    """Refresh the saved token and update the keychain."""
    token = keyring.get_password(SERVICE, "token")
    if not token:
        typer.echo("no saved token; run login first", err=True)
        raise typer.Exit(1)

    async def run() -> None:
        async with SmartHub() as hub:
            auth = await hub.refresh(token)
        keyring.set_password(SERVICE, "token", auth.authorization_token)
        typer.echo("token refreshed; keychain updated")

    try:
        asyncio.run(run())
    except AuthError as exc:
        typer.echo(f"refresh failed: {exc}", err=True)
        raise typer.Exit(1) from exc
    except httpx2.HTTPError as exc:
        typer.echo(f"request failed: {exc}", err=True)
        raise typer.Exit(1) from exc


@auth_app.command()
def logout() -> None:
    """Delete saved credentials and token from the keychain."""
    for name in ("user_id", "password", "token"):
        try:
            keyring.delete_password(SERVICE, name)
        except keyring.errors.PasswordDeleteError:
            pass
    typer.echo("keychain entries deleted")


@auth_app.command("show")
def show() -> None:
    """Show authentication status."""
    user_id = keyring.get_password(SERVICE, "user_id")
    token = keyring.get_password(SERVICE, "token")
    if not user_id:
        typer.echo("no saved credentials", err=True)
        raise typer.Exit(1)
    typer.echo(f"user: {user_id}")
    typer.echo(f"token: {token[:24]}..." if token else "token: none")
