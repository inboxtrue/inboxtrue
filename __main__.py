import json
import sys
from collections.abc import Iterable, Iterator
from typing import NoReturn

import click
from rich.console import Console
from rich.table import Table

from inboxtrue import auth, client, config

console = Console()
err = Console(stderr=True)

validate_columns = ('email', 'validity', 'is_disposable', 'is_consumer', 'is_domain_catchall', 'retry_after')

fmt_option = click.option(
    '--format', 'fmt',
    type=click.Choice(['auto', 'json', 'table']),
    default='auto',
    help='Output format. Defaults to table on TTY, NDJSON when piped.',
)


def effective_format(fmt: str) -> str:
    return fmt if fmt != 'auto' else ('table' if sys.stdout.isatty() else 'json')


def addresses(args: Iterable[str], stdin: Iterable[str]) -> Iterator[str]:
    '''Command-line addresses, with "-" (or no arguments at all) meaning one address per line on stdin.'''
    for arg in list(args) or ['-']:
        if arg == '-':
            yield from (line.strip() for line in stdin if line.strip() and not line.lstrip().startswith('#'))
        else:
            yield arg


def fail(message: str) -> NoReturn:
    err.print(f'[red]Error:[/red] {message}')
    sys.exit(1)


def report_api_error(exc: client.ApiError) -> NoReturn:
    hints = {
        401: 'Run: inboxtrue login (or check INBOXTRUE_API_KEY).',
        402: 'Out of credits. Top up at https://inboxtrue.com/balance.',
        403: 'This credential cannot use that endpoint.',
        429: 'Rate limited; wait a moment and retry.',
    }
    hint = hints.get(exc.status, 'Try again shortly.' if exc.status >= 500 else '')
    fail(f'{exc} ({exc.status}). {hint}'.strip())


@click.group(context_settings={'max_content_width': 120})
def cli():
    '''InboxTrue email validation from the terminal.

    Authenticate with `inboxtrue login` (browser), or set INBOXTRUE_API_KEY for scripts and servers.
    '''


@cli.command()
@click.option('--no-browser', is_flag=True, help='Only print the login URL instead of opening a browser.')
@click.option('--code', 'paste_code', is_flag=True,
              help='Approve in a browser on any machine and paste the code it shows (Docker, SSH).')
def login(no_browser: bool, paste_code: bool):  # noqa: FBT001
    '''Log in through the browser and store a session token for this API.

    By default the browser must run on the same machine as the CLI, since it hands the login back over 127.0.0.1. In
    Docker or over SSH, use --code. In CI, set INBOXTRUE_API_KEY instead.
    '''
    url = config.api_url()

    def announce(login_url: str):
        err.print('Opening the browser to approve the InboxTrue CLI. If it does not open, visit:')
        err.print(login_url, soft_wrap=True, highlight=False)

    def announce_code(login_url: str):
        err.print('Open this URL in a browser on any device and approve the InboxTrue CLI:')
        err.print(login_url, soft_wrap=True, highlight=False)

    def read_code() -> str:
        return click.prompt('Paste the code shown in the browser', err=True)

    try:
        if paste_code:
            auth.login_with_code(url, announce=announce_code, read_code=read_code)
        else:
            auth.login(url, open_browser=not no_browser, announce=announce)
    except auth.AuthError as exc:
        fail(str(exc))
    err.print(f'[green]Logged in[/green] to {url}.')


@cli.command()
def logout():
    '''Forget the stored session (revoke it under Connected apps on the dashboard /keys page).'''
    url = config.api_url()
    with config.credentials_lock():
        session = config.load_session(url)
        config.save_session(url, auth.client_fields(session) or None)
    err.print(f'Logged out of {url}.')


@cli.command()
@click.argument('emails', nargs=-1)
@click.option('--timeout', type=click.IntRange(1, 90), default=60, show_default=True,
              help='Seconds to wait on each mail server.')
@fmt_option
def validate(emails: tuple[str, ...], timeout: int, fmt: str):
    '''Validate email addresses (1 paid credit per checked address; malformed ones and failed checks are free).

    With no paid credits left, validations are free under a much lower rate limit.

    Pass "-" or pipe one address per line on stdin.
    '''
    effective = effective_format(fmt)
    rows = []
    try:
        for email in addresses(emails, sys.stdin):
            if effective == 'table':
                with err.status(f'Validating {email}'):
                    rows.append(client.validate(email, timeout))
            else:
                sys.stdout.write(json.dumps(client.validate(email, timeout)) + '\n')
                sys.stdout.flush()
    except client.ApiError as exc:
        report_api_error(exc)
    except auth.AuthError as exc:
        fail(str(exc))
    finally:
        if rows:
            table = Table(*validate_columns)
            for row in rows:
                table.add_row(*(str(row.get(c, '')) for c in validate_columns))
            console.print(table)


@cli.command()
@fmt_option
def credits(fmt: str):
    '''Show remaining credits.'''
    try:
        result = client.credits()
    except client.ApiError as exc:
        report_api_error(exc)
    except auth.AuthError as exc:
        fail(str(exc))
    if effective_format(fmt) == 'json':
        sys.stdout.write(json.dumps(result) + '\n')
    else:
        console.print(f'{result["remaining_credits"]} credits remaining')


@cli.group('config')
def config_group():
    '''Read or change settings in ~/.config/inboxtrue/config.json.'''


@config_group.command('get')
@click.argument('key', type=click.Choice([key for key, _ in config.config_keys]))
def config_get(key: str):
    console.print(config.read_json(config.config_path()).get(key, ''))


@config_group.command('set')
@click.argument('key', type=click.Choice([key for key, _ in config.config_keys]))
@click.argument('value')
def config_set(key: str, value: str):
    data = {**config.read_json(config.config_path()), key: value.rstrip('/')}
    config.write_json_private(config.config_path(), data)
    err.print(f'{key} = {data[key]}')


def test_addresses():
    assert list(addresses(['a@x.com', 'b@x.com'], [])) == ['a@x.com', 'b@x.com']
    assert list(addresses([], ['a@x.com\n', '\n', '# note\n', ' b@x.com '])) == ['a@x.com', 'b@x.com']
    assert list(addresses(['z@x.com', '-'], ['a@x.com\n'])) == ['z@x.com', 'a@x.com']


if __name__ == '__main__':
    cli()
