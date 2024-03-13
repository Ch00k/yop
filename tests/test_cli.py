from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from yop.cli import cli
from yop.types import Credential


def create_test_data() -> tuple[list[Credential], list[Credential], str]:
    store_cred_1 = Credential(
        issuer="firefox.com", name="rick@c137.space", secret="foo", store_path=Path("firefox.com")
    )
    store_cred_2 = Credential(issuer="amazon.com", name="morty@aol.com", secret="bar", store_path=Path("amazon.com"))
    store_cred_3 = Credential(issuer="google.com", name="summer@aol.com", secret="baz", store_path=Path("google.com"))

    yubikey_cred_1 = Credential(issuer="firefox.com", name="rick@c137.space")
    yubikey_cred_2 = Credential(issuer="amazon.com", name="morty@aol.com")
    yubikey_cred_3 = Credential(issuer="ebay.com", name="jerry@aol.com")

    output = """Reading credentials in /tmp and in My YubiKey. This may take a moment...

Credential                   Store        YubiKey
---------------------------  -----------  ---------
firefox.com:rick@c137.space  firefox.com  y
amazon.com:morty@aol.com     amazon.com   y
google.com:summer@aol.com    google.com   n
ebay.com:jerry@aol.com                    y
"""

    return [store_cred_1, store_cred_2, store_cred_3], [yubikey_cred_1, yubikey_cred_2, yubikey_cred_3], output


def configure_mocks(
    mock_store: MagicMock,
    mock_yubikey: MagicMock,
    store_credentials: list[Credential],
    yubikey_credentials: list[Credential],
) -> MagicMock:
    mock_store.return_value.collect_credentials.return_value = store_credentials

    yubikey = MagicMock(info="My YubiKey")
    yubikey_session = MagicMock()
    yubikey.collect_credentials.return_value = yubikey_credentials
    yubikey.get_session.return_value.__enter__.return_value = yubikey_session
    mock_yubikey.detect.return_value = yubikey

    return yubikey_session


@patch("yop.cli.Store")
@patch("yop.cli.YubiKey")
def test_all(m_yubikey: MagicMock, m_store: MagicMock) -> None:
    store_credentials, yubikey_credentials, output = create_test_data()
    yubikey_session = configure_mocks(m_store, m_yubikey, store_credentials, yubikey_credentials)

    runner = CliRunner()
    result = runner.invoke(cli, ["/tmp", "--really", "--delete"])

    expected_output = (
        output
        + """
Adding credentials to YubiKey
google.com:summer@aol.com

Deleting credentials from YubiKey
ebay.com:jerry@aol.com
"""
    )

    assert result.exit_code == 0
    assert result.output == expected_output

    yubikey_session.put_credential.assert_called_once_with(store_credentials[2].as_yubikey_credential_data())
    yubikey_session.delete_credential.assert_called_once_with(yubikey_credentials[2].id.encode())


@patch("yop.cli.Store")
@patch("yop.cli.YubiKey")
def test_no_delete(m_yubikey: MagicMock, m_store: MagicMock) -> None:
    store_credentials, yubikey_credentials, output = create_test_data()
    yubikey_session = configure_mocks(m_store, m_yubikey, store_credentials, yubikey_credentials)

    runner = CliRunner()
    result = runner.invoke(cli, ["/tmp", "--really"])

    expected_output = (
        output
        + """
Adding credentials to YubiKey
google.com:summer@aol.com

Skipping deletion. Use '--delete' to force
"""
    )

    assert result.exit_code == 0
    assert result.output == expected_output

    yubikey_session.put_credential.assert_called_once_with(store_credentials[2].as_yubikey_credential_data())
    yubikey_session.delete_credential.assert_not_called()


@patch("yop.cli.Store")
@patch("yop.cli.YubiKey")
def test_no_really(m_yubikey: MagicMock, m_store: MagicMock) -> None:
    store_credentials, yubikey_credentials, output = create_test_data()
    yubikey_session = configure_mocks(m_store, m_yubikey, store_credentials, yubikey_credentials)

    runner = CliRunner()
    result = runner.invoke(cli, ["/tmp"])

    expected_output = (
        output
        + """
In dry-run mode. Use '--really' to disable
"""
    )

    assert result.exit_code == 0
    assert result.output == expected_output

    yubikey_session.put_credential.assert_not_called()
    yubikey_session.delete_credential.assert_not_called()
