"""Account subcommands for the DMEA SmartHub CLI."""

import asyncio

import keyring
import typer

from dmea_smarthub import Account, AuthInfo, AuthResponse, SmartHub
from dmea_smarthub.cli.auth import SERVICE

accounts_app = typer.Typer(no_args_is_help=True)


@accounts_app.command("list")
def list_accounts() -> None:
    """List accounts on the SmartHub profile."""
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

    async def run() -> list[Account]:
        async with SmartHub(
            auth=auth,
            auth_info=AuthInfo(user_id=user_id, password=password),
        ) as hub:
            accounts = await hub.list_accounts()
            if hub.auth:
                keyring.set_password(SERVICE, "token", hub.auth.authorization_token)
            return accounts

    try:
        accounts = asyncio.run(run())
    except Exception as exc:
        typer.echo(f"failed: {exc}", err=True)
        raise typer.Exit(1) from exc

    for acct in accounts:
        typer.echo(f"{acct.account}  locations: {', '.join(acct.service_locations)}")
    typer.echo(f"{len(accounts)} account(s)", err=True)
