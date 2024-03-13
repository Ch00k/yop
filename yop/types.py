import subprocess
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from ykman.base import YkmanDevice
from ykman.device import list_all_devices
from yubikit.core.smartcard import SmartCardConnection
from yubikit.oath import HASH_ALGORITHM, OATH_TYPE
from yubikit.oath import Credential as YubikeyCredential
from yubikit.oath import CredentialData, OathSession, parse_b32_key
from yubikit.support import get_name, read_info


class CredentialParseError(Exception):
    pass


class YopError(Exception):
    pass


@dataclass
class Credential:
    issuer: str
    name: str
    secret: Optional[str] = None
    store_path: Optional[Path] = None

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
        return self.id

    @property
    def id(self) -> str:
        return f"{self.issuer}:{self.name}"

    @staticmethod
    def from_path(path: Path) -> "Credential":
        resp = subprocess.run(["pass", "show", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        resp.check_returncode()

        name, secret = Credential.parse_credential_data(resp.stdout.decode())
        return Credential(issuer=path.name, name=name, secret=secret, store_path=path)

    @staticmethod
    def from_yubikey_credential(yubikey_credential: YubikeyCredential) -> "Credential":
        if yubikey_credential.issuer is None:
            raise YopError("Credential issuer is not set")

        return Credential(issuer=yubikey_credential.issuer, name=yubikey_credential.name)

    @staticmethod
    def parse_credential_data(data: str) -> Tuple[str, str]:
        lines = [line.strip() for line in data.splitlines() if not line.isspace()]
        if not lines:
            raise CredentialParseError("File is empty")

        secret = lines.pop(0)
        try:
            parse_b32_key(secret)
        except Exception:
            raise CredentialParseError("Value found is not an OTP secret")

        if not lines:
            raise CredentialParseError("File does not contain a username")

        for line in lines:
            if line.lower().startswith(("name:", "username:")):
                name = line.split(":")[-1].strip()
        else:
            name = lines[0]

        return name, secret

    def write_to_yubikey(self, session: OathSession) -> None:
        session.put_credential(self.as_yubikey_credential_data())

    def delete_from_yubikey(self, session: OathSession) -> None:
        session.delete_credential(self.id.encode())

    def as_yubikey_credential_data(self) -> CredentialData:
        if self.secret is None:
            raise YopError("Credential secret is not set")

        return CredentialData(
            name=self.id,
            oath_type=OATH_TYPE.TOTP,
            hash_algorithm=HASH_ALGORITHM.SHA1,
            secret=self.secret.encode(),
        )


@dataclass
class Store:
    path: Path

    def __post_init__(self) -> None:
        if not (self.path / ".gpg-id").exists():
            raise YopError(f"{self.path} is not a pass directory")

    def collect_credentials(self) -> List[Credential]:
        credentials = []

        for gpg_file in Path(self.path).rglob("*.gpg"):
            pass_path = gpg_file.relative_to(self.path).with_suffix("")

            try:
                credentials.append(Credential.from_path(pass_path))
            except subprocess.CalledProcessError as e:
                err = ". ".join([m.decode().replace("\n", ". ") for m in (e.stdout, e.stderr) if m])
                raise YopError(f"Failed to read credential {pass_path}: {err}")
            except CredentialParseError as e:
                raise YopError(f"Failed to parse credential {pass_path}: {e}")

        return credentials


@dataclass
class YubiKey:
    device: YkmanDevice
    info: str = field(init=False)

    def __post_init__(self) -> None:
        with self.get_connection() as conn:
            info = read_info(conn, self.device.pid)
            key_type = None if self.device.pid is None else self.device.pid.yubikey_type
            self.info = f"{get_name(info, key_type)} (serial number {info.serial})"

    @staticmethod
    def detect() -> "YubiKey":
        connected_yubikeys = list_all_devices()

        if not connected_yubikeys:
            raise YopError("No YubiKeys found")

        if len(connected_yubikeys) > 1:
            raise YopError("Multiple YubiKeys found")

        return YubiKey(device=connected_yubikeys[0][0])

    @contextmanager
    def get_connection(self) -> Iterator[SmartCardConnection]:
        yield self.device.open_connection(SmartCardConnection)

    @contextmanager
    def get_session(self) -> Iterator[OathSession]:
        with self.get_connection() as conn:
            yield OathSession(conn)

    def collect_credentials(self) -> List[Credential]:
        with self.get_session() as session:
            return [Credential.from_yubikey_credential(c) for c in session.list_credentials()]
