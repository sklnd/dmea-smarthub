"""CLI for exercising the DMEA SmartHub library."""

import logging

import typer
from rich.logging import RichHandler

from dmea_smarthub.cli.accounts import accounts_app
from dmea_smarthub.cli.auth import auth_app

app = typer.Typer(no_args_is_help=True)
app.add_typer(auth_app, name="auth", help="Login, logout, token refresh.")
app.add_typer(accounts_app, name="accounts", help="Account lookups.")


@app.callback()
def _root(
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Enable debug logging."
    ),
) -> None:
    """CLI for exercising the DMEA SmartHub library."""
    if verbose:
        logging.basicConfig(
            level=logging.DEBUG,
            format="%(message)s",
            handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
            force=True,
        )


def main() -> None:
    app()


if __name__ == "__main__":
    main()
