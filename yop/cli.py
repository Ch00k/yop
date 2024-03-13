import os
import sys
from pathlib import Path

import click

from .types import Store, YopError, YubiKey
from .utils import combine_credentials, find_actionable_credentials, generate_table


@click.command
@click.argument(
    "store",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, resolve_path=True, path_type=Path),
)
@click.option(
    "--really",
    is_flag=True,
    show_default=True,
    default=False,
    help="Really execute the sync (aka the opposite of dry-run)",
)
@click.option(
    "--delete",
    is_flag=True,
    show_default=True,
    default=False,
    help="Delete YubiKey credentials not present in pass",
)
def cli(store: Path, really: bool, delete: bool) -> None:
    """
    Synchronize OTP credentials in the currently plugged in YubiKey (one YubiKey at a time is supported), with those
    stored in pass (https://www.passwordstore.org/), at the filesystem path specified by STORE.

    The OTP credentials that are created on the YubiKey, follow the naming scheme of the `ykman oath` command line
    tool: `<issuer>:<name>` (e.g., `paypal.com:me@example.com`).

    In pass, the filename is assumed to be the issuer, the first line of the file - the secret. If a line in the file
    starts with `user:` or `username:`, the value after `: ` is assumed to be the credential name; otherwise, the entire
    second line is assumed to be the name.

    Dry-run is the default, use '--really' to disable. Credentials, not found in pass, are not deleted from the YubiKey.
    Use `--delete` to force.

    Parsing pass credentials is atomic: the operation is aborted if parsing fails, or if pass contains more than 32
    credentials (YubiKey OTP app limitation).
    """
    os.environ["PASSWORD_STORE_DIR"] = str(store)

    try:
        credential_store = Store(store)
    except YopError as e:
        click.echo(click.style(e, fg="red"))
        sys.exit(1)

    try:
        yubikey = YubiKey.detect()
    except YopError as e:
        click.echo(click.style(e, fg="red"))
        sys.exit(1)

    click.echo(f"Reading credentials in {store} and in {yubikey.info}. This may take a moment...")
    click.echo()

    try:
        store_credentials = credential_store.collect_credentials()
    except YopError as e:
        click.echo(click.style(e, fg="red"))
        sys.exit(1)

    num_store_credentials = len(store_credentials)

    if num_store_credentials > 32:
        msg = f"YubiKey OTP app allows up to 32 credentials, but {num_store_credentials} credentials found in {store}"
        click.echo(click.style(msg, fg="red"))
        sys.exit(1)

    yubikey_credentials = yubikey.collect_credentials()

    combined_credentials = combine_credentials(store_credentials, yubikey_credentials)

    click.echo(generate_table(combined_credentials))

    to_add, to_delete = find_actionable_credentials(combined_credentials)

    if not any((to_add, to_delete)):
        click.echo()
        click.echo(click.style(f"Credentials on YubiKey are in sync with {store}", fg="green"))
        sys.exit()

    if really:
        click.echo()

        with yubikey.get_session() as session:
            if to_add:
                click.echo("Adding credentials to YubiKey")
                for cred in to_add:
                    click.echo(cred)
                    cred.write_to_yubikey(session)

            if to_delete:
                # Separate the two with an empty line
                if to_add:
                    click.echo()

                if delete:
                    click.echo("Deleting credentials from YubiKey")
                    for cred in to_delete:
                        click.echo(cred)
                        cred.delete_from_yubikey(session)
                else:
                    click.echo(click.style("Skipping deletion. Use '--delete' to force", fg="yellow"))

    else:
        click.echo()
        click.echo(click.style("In dry-run mode. Use '--really' to disable", fg="yellow"))


# https://stackoverflow.com/a/45881691
def safe_cli() -> None:
    try:
        cli()
    except Exception as e:
        click.echo(click.style(e, fg="red"))
