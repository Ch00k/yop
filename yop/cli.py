import contextlib
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

import click
from ykman.base import YkmanDevice
from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.management import DeviceInfo
from yubikit.oath import HASH_ALGORITHM, OATH_TYPE
from yubikit.oath import Credential as YubikeyCredential
from yubikit.oath import CredentialData, OathSession
from yubikit.support import get_name, read_info

from .utils import parse_otp_credential_data

CONTEXT_SETTINGS = {"max_content_width": 100}


@dataclass
class Credential:
    issuer: str
    name: str
    secret: Optional[str] = None

    def __hash__(self) -> int:
        return hash((self.issuer, self.name))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Credential):
            return NotImplemented

        return self.issuer == other.issuer and self.name == other.name

    def __repr__(self) -> str:
        secret = None if self.secret is None else "<REDACTED>"
        return f"Credential(issuer='{self.issuer}', name='{self.name}', secret={secret})"

    def __str__(self) -> str:
        return f"{self.issuer}:{self.name}"

    @property
    def id(self) -> str:
        return f"{self.issuer}:{self.name}"

    @staticmethod
    def from_path(path: Path) -> "Credential":
        pass_path = str(path).removesuffix(".gpg")
        resp = subprocess.run(["pass", "show", pass_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        resp.check_returncode()

        issuer = pass_path.split("/")[-1]
        name, secret = parse_otp_credential_data(resp.stdout.decode())

        return Credential(issuer=issuer, name=name, secret=secret)

    @staticmethod
    def from_yubikey_credential(yubikey_credential: YubikeyCredential) -> "Credential":
        if yubikey_credential.issuer is None:
            raise RuntimeError("No issuer!")

        return Credential(issuer=yubikey_credential.issuer, name=yubikey_credential.name)

    def as_yubikey_credential_data(self) -> CredentialData:
        if self.secret is None:
            raise RuntimeError("No secret!")

        return CredentialData(
            name=self.id,
            oath_type=OATH_TYPE.TOTP,
            hash_algorithm=HASH_ALGORITHM.SHA1,
            secret=self.secret.encode(),
        )


def find_yubikey() -> YkmanDevice:
    connected_yubikeys = list_all_devices()

    if not connected_yubikeys:
        raise RuntimeError("No YubiKeys found")

    if len(connected_yubikeys) > 1:
        raise RuntimeError("Multiple YubiKeys found")

    return connected_yubikeys[0][0]


@contextlib.contextmanager
def get_oath_session(yubikey: YkmanDevice) -> Iterator[tuple[DeviceInfo, OathSession]]:
    with yubikey.open_connection(SmartCardConnection) as conn:
        yield read_info(conn, yubikey.pid), OathSession(conn)


def find_all_password_store_credentials(path: Path) -> list[Path]:
    return list(Path(path).rglob("*.gpg"))


def check_if_password_store_path(_: click.Context, __: click.Parameter, val: Path) -> Path:
    if not (val / ".gpg-id").exists():
        raise RuntimeError()

    return val


@click.group(context_settings=CONTEXT_SETTINGS, invoke_without_command=True)
@click.argument(
    "store",
    type=click.Path(exists=True, file_okay=False, dir_okay=True, resolve_path=True, path_type=Path),
    callback=check_if_password_store_path,
)
@click.option(
    "--really",
    is_flag=True,
    show_default=True,
    default=False,
    help="Really perform the actions (aka the opposite of dry-run)",
)
@click.option(
    "-v",
    "--verbose",
    is_flag=True,
    show_default=True,
    default=False,
    help="Verbose output",
)
def cli(password_store: Path, really: bool, verbose: bool) -> None:
    """
    Synchronize OTP credentials in the currently plugged in YubiKey with those stored in pass
    (https://www.passwordstore.org/) at the filesystem path specified by STORE.

    Only one YubiKey is supported at a time.

    The OTP credentials on the YubiKey follow the naming scheme of the ykman oath command line tool: <issuer>:<name>
    (e.g., paypal.com:me@example.com).

    In the pass store, the filename is assumed to be the OTP issuer (a website or a resource). The first line of the
    encrypted file is assumed to be the OTP secret. If a line in the file starts with `user:` or `username:`, the value
    after `: ` is assumed to be the OTP credential name; otherwise, the entire second line is taken as the name.

    Dry-run mode is enabled by default. Use '--really' to execute the synchronization.
    """
    try:
        yubikey = find_yubikey()
    except RuntimeError as e:
        click.echo(click.style(e, fg="red"))
        sys.exit(1)

    os.environ["PASSWORD_STORE_DIR"] = str(password_store)

    password_store_credentials = []
    with click.progressbar(
        find_all_password_store_credentials(password_store), label=f"Reading credentials in {password_store}"
    ) as pass_creds:
        for cred_path in pass_creds:
            try:
                cred = Credential.from_path(cred_path.relative_to(password_store))
            except subprocess.CalledProcessError as e:
                click.echo()  # otherwise the message will be on the same line as progress bar

                message = ""
                if e.stdout:
                    message += e.stdout.decode()
                    message += "\n"
                if e.stderr:
                    message += e.stderr.decode()

                click.echo(click.style(message, fg="red"))
                sys.exit(1)

            password_store_credentials.append(cred)

    if verbose:
        for cred in password_store_credentials:
            click.echo(cred)
        click.echo()

    with yubikey.open_connection(SmartCardConnection) as conn:
        info = read_info(conn, yubikey.pid)
        key_type = None if yubikey.pid is None else yubikey.pid.yubikey_type
        yubikey_info = f"{get_name(info, key_type)} (serial number {info.serial})"

        session = OathSession(conn)

        with click.progressbar(session.list_credentials(), label=f"Reading credentials in {yubikey_info}") as yk_creds:
            yubikey_credentials = [Credential.from_yubikey_credential(c) for c in yk_creds]

        if verbose:
            for cred in yubikey_credentials:
                click.echo(cred)
            click.echo()

        to_add = set(password_store_credentials) - set(yubikey_credentials)
        to_remove = set(yubikey_credentials) - set(password_store_credentials)

        if not any((to_add, to_remove)):
            click.echo()
            click.echo("Credentials in store and on YubiKey are in sync")
            sys.exit()

        click.echo()

        if to_add:
            click.echo("The following credentials will be added to Yubikey:")
            for cred in to_add:
                click.echo(cred)

            if really:
                with click.progressbar(to_add, label="Adding credentials to YubiKey") as creds:
                    [session.put_credential(cred.as_yubikey_credential_data()) for cred in creds]

        if to_remove:
            click.echo("The following credentials will be removed from Yubikey:")
            for cred in to_remove:
                click.echo(cred)

            if really:
                with click.progressbar(to_remove, label="Removing credentials from YubiKey") as creds:
                    for cred in creds:
                        session.delete_credential(cred.id.encode())

        if not really:
            click.echo()
            click.echo(click.style("In dry-run mode. Pass '--really' to perform the actions", fg="yellow"))


# https://stackoverflow.com/a/45881691
def safe_cli() -> None:
    try:
        cli()
    except Exception as e:
        click.echo(click.style(e, fg="red"))
