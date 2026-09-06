"""Account subcommands for the DMEA SmartHub CLI."""

import asyncio

import typer

from dmea_smarthub import Account
from dmea_smarthub.cli.common import load_client, save_token

accounts_app = typer.Typer(no_args_is_help=True)


@accounts_app.command("list")
def list_accounts() -> None:
    """List accounts on the SmartHub profile."""
    hub = load_client()

    async def run() -> list[Account]:
        async with hub:
            accounts = await hub.list_accounts()
            save_token(hub)
            return accounts

    try:
        accounts = asyncio.run(run())
    except Exception as exc:
        typer.echo(f"failed: {exc}", err=True)
        raise typer.Exit(1) from exc

    for acct in accounts:
        typer.echo(f"{acct.account}  locations: {', '.join(acct.service_locations)}")
    typer.echo(f"{len(accounts)} account(s)", err=True)
