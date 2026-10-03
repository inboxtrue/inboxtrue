import contextlib
import errno
import json
import os
import sys
import tempfile
from collections.abc import Iterator
from typing import IO

if sys.platform == 'win32':
    import msvcrt  # pylint: disable=import-error
else:
    import fcntl

default_api_url = 'https://api.inboxtrue.com'
config_keys = (('api_url', 'API origin, eg https://api.inboxtrue.com (env INBOXTRUE_API_URL wins)'),)


def config_dir() -> str:
    base = os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config')
    return os.path.join(base, 'inboxtrue')


def config_path() -> str:
    return os.path.join(config_dir(), 'config.json')


def credentials_path() -> str:
    return os.path.join(config_dir(), 'credentials.json')


def read_json(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError as exc:
        raise SystemExit(f'{path} is not valid JSON: {exc}') from exc


def write_json_private(path: str, data: dict):
    '''Atomically replace path with data, readable only by the current user (it may hold tokens).'''
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix='.tmp-')
    replaced = False
    try:
        with os.fdopen(fd, 'w') as f:
            json.dump(data, f, indent=2)
            f.write('\n')
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        replaced = True
    finally:
        if not replaced:
            os.unlink(tmp)


@contextlib.contextmanager
def credentials_lock() -> Iterator[None]:
    '''Serialize credential updates across concurrent CLI processes.

    Refresh tokens rotate on use and the server revokes the whole grant when a rotated-out one comes back, so two
    processes refreshing at once (eg under xargs -P) must not both spend the same refresh token.
    '''
    os.makedirs(config_dir(), mode=0o700, exist_ok=True)
    with open(os.path.join(config_dir(), '.credentials.lock'), 'w') as lock:
        lock_file(lock)
        try:
            yield
        finally:
            unlock_file(lock)


if sys.platform == 'win32':
    def try_lock_file(f: IO) -> bool:
        try:
            msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
        except OSError as exc:
            if exc.errno != errno.EDEADLOCK:
                raise
            return False
        return True

    def lock_file(f: IO):
        # LK_LOCK gives up with EDEADLOCK after about 10 seconds, so keep waiting like flock does.
        while not try_lock_file(f):
            pass

    def unlock_file(f: IO):
        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
else:
    def lock_file(f: IO):
        fcntl.flock(f, fcntl.LOCK_EX)

    def unlock_file(f: IO):
        fcntl.flock(f, fcntl.LOCK_UN)


def api_url() -> str:
    url = os.environ.get('INBOXTRUE_API_URL') or read_json(config_path()).get('api_url') or default_api_url
    return url.rstrip('/')


def api_key() -> str | None:
    return os.environ.get('INBOXTRUE_API_KEY', '').strip() or None


def load_session(url: str) -> dict:
    return read_json(credentials_path()).get(url, {})


def save_session(url: str, session: dict | None):
    creds = read_json(credentials_path())
    if session is None:
        creds.pop(url, None)
    else:
        creds[url] = session
    write_json_private(credentials_path(), creds)


def test_credentials_are_private_and_keyed_by_api_url():
    with tempfile.TemporaryDirectory() as home:
        old = os.environ.get('XDG_CONFIG_HOME')
        os.environ['XDG_CONFIG_HOME'] = home
        try:
            save_session('https://api.inboxtrue.com', {'access_token': 'a'})
            save_session('http://localhost:3080', {'access_token': 'b'})
            if sys.platform != 'win32':
                assert os.stat(credentials_path()).st_mode & 0o777 == 0o600
            assert load_session('https://api.inboxtrue.com') == {'access_token': 'a'}
            save_session('https://api.inboxtrue.com', None)
            assert load_session('https://api.inboxtrue.com') == {}
            assert load_session('http://localhost:3080') == {'access_token': 'b'}
        finally:
            if old is None:
                os.environ.pop('XDG_CONFIG_HOME')
            else:
                os.environ['XDG_CONFIG_HOME'] = old
