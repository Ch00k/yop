from typing import Dict, List, Tuple

import click
from tabulate import tabulate

from .types import Credential


def combine_credentials(store_credentials: List[Credential], yubikey_credentials: List[Credential]) -> Dict:
    credentials = {cred: {"store_path": cred.store_path, "exists_in_yubikey": False} for cred in store_credentials}

    for cred in yubikey_credentials:
        if cred in credentials:
            credentials[cred]["exists_in_yubikey"] = True
        else:
            credentials[cred] = {"store_path": None, "exists_in_yubikey": True}

    return credentials


def generate_table(credential_data: Dict) -> str:
    table_header = ["Credential", "Store", "YubiKey"]
    table = []

    for cred_as_str, meta in credential_data.items():
        table.append(
            [
                cred_as_str,
                meta["store_path"] if meta["store_path"] else click.style("n/a", fg="red"),
                "y" if meta["exists_in_yubikey"] else click.style("n", fg="red"),
            ]
        )

    return tabulate(table, headers=table_header)


def find_actionable_credentials(credentials: Dict) -> Tuple[List[Credential], List[Credential]]:
    to_add = [cred for cred, meta in credentials.items() if not meta["exists_in_yubikey"]]
    to_delete = [cred for cred, meta in credentials.items() if meta["exists_in_yubikey"] and meta["store_path"] is None]
    return to_add, to_delete
