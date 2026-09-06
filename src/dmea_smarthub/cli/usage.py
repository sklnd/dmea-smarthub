"""Usage subcommands for the DMEA SmartHub CLI."""

import asyncio
from datetime import datetime, timedelta
from typing import Annotated

import typer

from dmea_smarthub import Aggregation, TimeRange, UsageComplete
from dmea_smarthub.cli.common import load_client, save_token

usage_app = typer.Typer(no_args_is_help=True)


@usage_app.command("list")
def list_usage(
    location: Annotated[
        str, typer.Option("--location", "-l", help="Service location number.")
    ],
    account: Annotated[
        str | None,
        typer.Option("--account", "-a", help="Account number (derived if omitted)."),
    ] = None,
    aggregation: Annotated[
        Aggregation, typer.Option("--aggregation", case_sensitive=False)
    ] = Aggregation.HOURLY,
    start: Annotated[
        datetime | None, typer.Option("--start", help="Defaults to 24h before --end.")
    ] = None,
    end: Annotated[
        datetime | None, typer.Option("--end", help="Defaults to now.")
    ] = None,
) -> None:
    """Fetch usage data for a service location."""
    # usage data is only available for completed days, so default to local midnight
    end = end or datetime.now().astimezone().replace(
        hour=0, minute=0, second=0, microsecond=0
    )
    start = start or end - timedelta(days=1)
    hub = load_client()

    async def run() -> UsageComplete:
        async with hub:
            usage = await hub.get_usage(
                location, TimeRange(start=start, end=end), aggregation, account=account
            )
            save_token(hub)
            return usage

    try:
        usage = asyncio.run(run())
    except Exception as exc:
        typer.echo(f"failed: {exc}", err=True)
        raise typer.Exit(1) from exc

    series = usage.usage_series
    if series is None:
        typer.echo(f"no usage data in response (status={usage.status})", err=True)
        raise typer.Exit(1)
    for point in series.data:
        typer.echo(f"{point.timestamp:%Y-%m-%d %H:%M}  {point.value} kWh")
    typer.echo(f"{len(series.data)} point(s) [{series.name}]", err=True)
