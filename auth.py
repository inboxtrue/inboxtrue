'''
OAuth for the CLI: discover the authorization server from the API's RFC 9728 metadata, register once as a public
client (RFC 7591), log in through the browser with a loopback redirect and PKCE (RFC 8252, RFC 7636), and keep the
access token fresh with rotating refresh tokens.
'''

import base64
import hashlib
import http.server
import json
import secrets
import threading
import time
import urllib.parse
import webbrowser
from dataclasses import dataclass

import urllib3

from inboxtrue import config

client_name = 'InboxTrue CLI'
loopback_redirect = 'http://127.0.0.1/callback'
login_timeout = 300
refresh_margin = 60


class AuthError(Exception):
    def __init__(self, message: str, *, error: str | None = None, status: int | None = None):
        super().__init__(message)
        self.error = error
        self.status = status


@dataclass(frozen=True, slots=True)
class Pkce:
    verifier: str
    challenge: str


@dataclass(frozen=True, slots=True)
class Callback:
    params: dict[str, str]


def new_pkce() -> Pkce:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return Pkce(verifier, base64.urlsafe_b64encode(digest).rstrip(b'=').decode())


def pool_manager() -> urllib3.PoolManager:
    return urllib3.PoolManager(timeout=urllib3.Timeout(connect=10, read=30), retries=False)


def get_json(pool: urllib3.PoolManager, url: str) -> dict:
    resp = pool.request('GET', url)
    if resp.status != 200:
        raise AuthError(f'GET {url} answered HTTP {resp.status}')
    return resp.json()


def discover(pool: urllib3.PoolManager, api_url: str) -> dict:
    '''Authorization server metadata for the API, found the same way MCP clients find it.'''
    resource = get_json(pool, f'{api_url}/.well-known/oauth-protected-resource')
    issuer = resource['authorization_servers'][0]
    metadata = get_json(pool, f'{issuer}/.well-known/oauth-authorization-server')
    if metadata.get('issuer') != issuer:
        raise AuthError(f'authorization server metadata names issuer {metadata.get("issuer")!r}, expected {issuer!r}')
    return metadata


def register(pool: urllib3.PoolManager, metadata: dict) -> str:
    resp = pool.request('POST', metadata['registration_endpoint'], json={
        'client_name': client_name,
        'redirect_uris': [loopback_redirect],
        'grant_types': ['authorization_code', 'refresh_token'],
        'response_types': ['code'],
        'token_endpoint_auth_method': 'none',
    })
    if resp.status != 201:
        raise AuthError(f'client registration failed: HTTP {resp.status} {resp.data.decode(errors="replace")}')
    return resp.json()['client_id']


def token_request(pool: urllib3.PoolManager, token_endpoint: str, fields: dict[str, str]) -> dict:
    resp = pool.request_encode_body('POST', token_endpoint, fields=fields, encode_multipart=False)
    try:
        body = resp.json()
    except ValueError:
        body = {}
    if not isinstance(body, dict):
        body = {}
    if resp.status != 200:
        message = body.get('error_description') or body.get('error') or f'token endpoint HTTP {resp.status}'
        raise AuthError(message, error=body.get('error'), status=resp.status)
    if not all(isinstance(body.get(k), str) for k in ('access_token', 'refresh_token')) \
            or not isinstance(body.get('expires_in'), int):
        raise AuthError('token endpoint returned an unusable response', status=200)
    return body


def refresh_failure(error: str | None, status: int | None) -> str:
    '''How to treat a failed refresh: 'revoked' or 'ambiguous' (drop the stored tokens), or 'transient' (keep them).

    'ambiguous' means the server may have rotated the refresh token without us seeing the new one (a lost or unusable
    response, or a server error after the backend may have committed); presenting the old token again would make the
    server revoke the whole grant as stolen, so it must not be reused. status None stands for a transport failure after
    the request was sent.
    '''
    if error == 'invalid_grant':
        return 'revoked'
    if status is None or status == 200 or status >= 500:
        return 'ambiguous'
    return 'transient'


def transport_failure(exc: urllib3.exceptions.HTTPError) -> str:
    '''Failures to connect (DNS, refused, connect timeout) happen before the request is sent, so nothing rotated.'''
    return 'transient' if isinstance(exc, urllib3.exceptions.ConnectTimeoutError) else refresh_failure(None, None)


def refresh_error(api_url: str, client_id: str, failure: str, detail: str) -> AuthError:
    '''Drop the stored tokens unless the failure was transient, and describe what the user should do.'''
    if failure == 'transient':
        return AuthError(f'could not refresh the session ({detail}); try again shortly')
    config.save_session(api_url, {'client_id': client_id})
    if failure == 'revoked':
        return AuthError(f'session expired or revoked ({detail}); run inboxtrue login')
    return AuthError(f'lost contact while refreshing the session ({detail}); run inboxtrue login')


def state_matches(received: str, expected: str) -> bool:
    return secrets.compare_digest(received.encode(), expected.encode())


def session_from_tokens(tokens: dict, client_id: str, token_endpoint: str) -> dict:
    return {
        'client_id': client_id,
        'token_endpoint': token_endpoint,
        'access_token': tokens['access_token'],
        'refresh_token': tokens['refresh_token'],
        'expires_at': time.time() + tokens['expires_in'],
    }


def wait_for_callback(server: http.server.HTTPServer) -> Callback:
    '''Serve requests on the loopback listener until the browser lands on /callback.'''
    received: list[Callback] = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            if parsed.path != '/callback':
                self.send_error(404)
                return
            received.append(Callback(dict(urllib.parse.parse_qsl(parsed.query))))
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(b'<p>InboxTrue CLI: done. You can close this tab and return to the terminal.</p>')

        def log_message(self, format, *args):
            pass

    server.RequestHandlerClass = Handler
    server.timeout = 1
    deadline = time.monotonic() + login_timeout
    while not received:
        if time.monotonic() > deadline:
            raise AuthError(f'no answer from the browser within {login_timeout}s')
        server.handle_request()
    return received[0]


def login(api_url: str, *, open_browser: bool, announce) -> dict:
    pool = pool_manager()
    metadata = discover(pool, api_url)
    session = config.load_session(api_url)
    client_id = session.get('client_id') or register(pool, metadata)
    pkce = new_pkce()
    state = secrets.token_urlsafe(24)
    with http.server.HTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler) as server:
        redirect_uri = f'http://127.0.0.1:{server.server_address[1]}/callback'
        url = metadata['authorization_endpoint'] + '?' + urllib.parse.urlencode({
            'response_type': 'code',
            'client_id': client_id,
            'redirect_uri': redirect_uri,
            'code_challenge': pkce.challenge,
            'code_challenge_method': 'S256',
            'state': state,
            'scope': ' '.join(metadata.get('scopes_supported', [])),
            'resource': api_url,
        })
        announce(url)
        if open_browser:
            threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
        callback = wait_for_callback(server)
    params = callback.params
    if not state_matches(params.get('state', ''), state):
        raise AuthError('the browser returned a different login attempt (state mismatch); run inboxtrue login again')
    if 'iss' in params and params['iss'] != metadata['issuer']:
        raise AuthError(f'response came from issuer {params["iss"]!r}, expected {metadata["issuer"]!r}')
    if 'error' in params:
        raise AuthError(params.get('error_description') or params['error'])
    tokens = token_request(pool, metadata['token_endpoint'], {
        'grant_type': 'authorization_code',
        'code': params['code'],
        'redirect_uri': redirect_uri,
        'client_id': client_id,
        'code_verifier': pkce.verifier,
    })
    new_session = session_from_tokens(tokens, client_id, metadata['token_endpoint'])
    with config.credentials_lock():
        config.save_session(api_url, new_session)
    return new_session


def access_token(api_url: str, *, force_refresh: bool = False) -> str:
    '''A usable access token, refreshing it (once, under a cross-process lock) when it is about to expire.'''
    session = config.load_session(api_url)
    if not session.get('refresh_token'):
        raise AuthError('not logged in; run inboxtrue login (or set INBOXTRUE_API_KEY)')
    if not force_refresh and session['expires_at'] - refresh_margin > time.time():
        return session['access_token']
    with config.credentials_lock():
        current = config.load_session(api_url)
        if not current.get('refresh_token'):
            raise AuthError('not logged in; run inboxtrue login (or set INBOXTRUE_API_KEY)')
        if current['refresh_token'] != session['refresh_token']:
            return current['access_token']
        try:
            tokens = token_request(pool_manager(), session['token_endpoint'], {
                'grant_type': 'refresh_token',
                'refresh_token': session['refresh_token'],
                'client_id': session['client_id'],
            })
        except urllib3.exceptions.HTTPError as exc:
            raise refresh_error(api_url, session['client_id'], transport_failure(exc), str(exc)) from exc
        except AuthError as exc:
            failure = refresh_failure(exc.error, exc.status)
            raise refresh_error(api_url, session['client_id'], failure, str(exc)) from exc
        config.save_session(api_url, session_from_tokens(tokens, session['client_id'], session['token_endpoint']))
    return tokens['access_token']


def test_refresh_failure():
    assert refresh_failure('invalid_grant', 400) == 'revoked'
    assert refresh_failure(None, None) == 'ambiguous'
    assert refresh_failure(None, 504) == 'ambiguous'
    assert refresh_failure(None, 500) == 'ambiguous'
    assert refresh_failure(None, 503) == 'ambiguous'
    assert refresh_failure(None, 200) == 'ambiguous'
    assert refresh_failure(None, 429) == 'transient'
    assert refresh_failure('invalid_request', 400) == 'transient'


def test_transport_failure():
    pool = urllib3.PoolManager(timeout=urllib3.Timeout(connect=2, read=2), retries=False)
    try:
        pool.request('POST', 'http://127.0.0.1:1/')
    except urllib3.exceptions.HTTPError as exc:
        assert transport_failure(exc) == 'transient'
    assert transport_failure(urllib3.exceptions.ProtocolError('Connection aborted.')) == 'ambiguous'
    read_pool = urllib3.HTTPConnectionPool('127.0.0.1')
    assert transport_failure(urllib3.exceptions.ReadTimeoutError(read_pool, '/', 'read timed out')) == 'ambiguous'


def test_token_request_bodies():
    def answer(status: int, body: bytes):
        server = http.server.HTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler)

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                self.rfile.read(int(self.headers['Content-Length']))
                self.send_response(status)
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format, *args):
                pass

        server.RequestHandlerClass = Handler
        threading.Thread(target=server.handle_request, daemon=True).start()
        try:
            token_request(pool_manager(), f'http://127.0.0.1:{server.server_address[1]}/t', {})
        except AuthError as exc:
            return exc.status, str(exc)
        finally:
            server.server_close()
        return None

    assert answer(400, b'[]') == (400, 'token endpoint HTTP 400')
    assert answer(200, b'<html>ok</html>') == (200, 'token endpoint returned an unusable response')
    assert answer(200, b'{"access_token": "a"}') == (200, 'token endpoint returned an unusable response')


def test_state_matches():
    assert state_matches('abc', 'abc')
    assert not state_matches('abd', 'abc')
    assert not state_matches('caf\u00e9', 'abc')


def test_new_pkce():
    pkce = new_pkce()
    assert 43 <= len(pkce.verifier) <= 128
    assert len(pkce.challenge) == 43
    digest = hashlib.sha256(pkce.verifier.encode()).digest()
    assert pkce.challenge == base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
    assert new_pkce().verifier != pkce.verifier


def test_wait_for_callback():
    with http.server.HTTPServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler) as server:
        port = server.server_address[1]

        def browser():
            pool = urllib3.PoolManager()
            assert pool.request('GET', f'http://127.0.0.1:{port}/favicon.ico').status == 404
            assert pool.request('GET', f'http://127.0.0.1:{port}/callback?code=c&state=s').status == 200

        threading.Thread(target=browser, daemon=True).start()
        assert wait_for_callback(server).params == {'code': 'c', 'state': 's'}


def test_session_from_tokens():
    session = session_from_tokens(
        {'access_token': 'a', 'refresh_token': 'r', 'expires_in': 3600}, 'cid', 'https://x/b/oauth/token')
    assert session['access_token'] == 'a'
    assert 3500 < session['expires_at'] - time.time() <= 3600
    assert json.dumps(session)
