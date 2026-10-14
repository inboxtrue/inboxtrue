import os
import sys
import tempfile

from inboxtrue.config import credentials_path, load_session, save_session


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
