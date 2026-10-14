# InboxTrue CLI

Command-line client for the [InboxTrue](https://inboxtrue.com) email validation API.
Requires Python 3.10 or newer.

## Installation

Once published on PyPI, install the CLI with pipx:

```sh
pipx install inboxtrue
```

You can also install it with `python -m pip install inboxtrue` inside a virtual
environment. Both `inboxtrue` and `python -m inboxtrue` run the CLI.

## Authentication

Log in with a browser on the same machine:

```sh
inboxtrue login
```

Use `inboxtrue login --no-browser` to print the login URL without opening it.
For Docker or SSH, approve the login in a browser on any device and paste the
code it displays:

```sh
inboxtrue login --code
```

For scripts and CI, set `INBOXTRUE_API_KEY` to your API key. It takes precedence
over the saved browser session.

`inboxtrue logout` forgets the local tokens. To revoke the session on the server,
use Connected apps on the dashboard's `/keys` page.

## Validate addresses

```sh
inboxtrue validate alice@example.com bob@example.com
inboxtrue validate --timeout 90 alice@example.com
inboxtrue validate - < emails.txt
inboxtrue credits
```

Input files contain one address per line; blank lines and lines starting with
`#` are ignored. With no address arguments, `validate` reads standard input.

Output defaults to a table in a terminal and newline-delimited JSON when piped.
Use `--format json` or `--format table` to select the format explicitly:

```sh
inboxtrue validate --format json alice@example.com
inboxtrue credits --format json
```

Validation costs one paid credit per checked address. Malformed addresses and
checks that error out are free. Once paid credits run out, validations are free
under a much lower rate limit. `--timeout` controls the mail-server wait per
address, from 1 to 90 seconds; the default is 60 seconds.

## Configuration

```sh
inboxtrue config get api_url
inboxtrue config set api_url https://api.inboxtrue.com
inboxtrue --version
inboxtrue --help
```

The default API URL is `https://api.inboxtrue.com`. `config get` shows the saved
setting, which is empty until set. `INBOXTRUE_API_URL` overrides the saved setting.

Settings and credentials are stored under `$XDG_CONFIG_HOME/inboxtrue`, or
`~/.config/inboxtrue` when that variable is unset. Sessions are stored separately
for each API URL. Files are restricted to the current user on POSIX; on Windows,
credential privacy depends on the config directory's ACL.

## Development

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest
python -m build
python -m twine check --strict dist/*
```

On Windows, activate with `.venv\Scripts\Activate.ps1` in PowerShell instead.
CI tests the installed package on Linux, macOS, and Windows, and checks the
wheel built from the source distribution. Publishing is a separate manual step.

## License

[MIT](LICENSE).
