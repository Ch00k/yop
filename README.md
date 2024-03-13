# yop

**Y**ubiKey **O**TP **P**rovisioner, or _**yop**_ for short, is a command line tool that allows provisioning OTP
credentials, stored in [pass](https://www.passwordstore.org/), onto a YubiKey.

#### The tool solves the problem of keeping OTP credentials on multiple YubiKeys in sync.

If you are a YubiKey user, chances are you have more than one: definitely for redundancy, probably for convenience. If
you use your YubiKeys for OTP, then you proabably want to keep the OTP credentials on all of them in sync. One way of
achieving that is keeping your credentials' data in [pass](https://www.passwordstore.org/), and then provision it onto
your YubiKeys. _**yop**_ automates the process of keeping credentials on your YubiKeys in sync with your _pass_ store.

## Installation

Install [pipx](https://pipx.pypa.io/stable/installation/), then

```
pipx install yop
```

## Usage

Insert a YubiKey, then execute `yop`, pointing it to the _pass_ directory with your OTP credentials:

```
yop ~/.otp-store
```

## Inner workings and limitations

_**yop**_ assumes that the _pass_ store it sees is used exclusively for OTP credentials, i.e. it will not try to make a
distinction between an encrypted OTP credential and an encrypted password. If a value encountered is not a valid OTP
secret (a Base32 encoded string), parsing will fail. It is generally a good idea anyway, if using _pass_ for OTP
credentials, to at least keep them in a separate store.

The store can have arbitrary directory structure, but it must contain no more than 32 encrypted files (this is a
[limitation](https://support.yubico.com/hc/en-us/articles/360013790319-How-many-accounts-can-I-register-my-YubiKey-with)
of the YubiKey OATH application, that can only hold up to 32 credentials).

_**yop**_ relies on the following assumptions about the encrypted file:

- the file name (without the `.gpg` extension) is assumed to be the issuer
- the first line is assumed to be the secret
- if there is a line that starts with `user: ` or `username: `, the part after `: ` is assumed to be the username;
  otherwise the second line is assumed to be the username

#### Examples:

- `firefox.com.gpg`:

  ```
  FOOBARBAZQUX4217
  username: me@example.com
  ```

- `amazon.com.gpg`:

  ```
  FOOBARBAZQUX4217
  user: someoneelse@example.com
  ```

- `github.com.gpg`:
  ```
  FOOBARBAZQUX4217
  Ch00k
  ```

The sync operation is atomic: if a file cannot be parsed, the sync operation is aborted.

By default _**yop**_ runs in dry-run mode. Supplying the `--really` option disables dry-run.

By default _**yop**_ will try to write credentials, that are found in _pass_, but are not found on YubiKey, but it will
not delete those that are found on YubiKey, but not found in _pass_. To force deletion, supply the `--delete` option.

See the output of `yop --help` for mode details.
