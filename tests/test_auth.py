import base64
import hashlib
import http.server
import json
import threading
import time

import urllib3

from inboxtrue.auth import (
    AuthError, CallbackServer, client_fields, code_page_path, loopback_redirect, new_pkce, pasted_params,
    pool_manager, refresh_failure, reusable_client, session_from_tokens, state_matches,
    token_request, transport_failure, wait_for_callback,
)


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
    empty_refresh = b'{"access_token": "a", "refresh_token": "", "expires_in": 3600}'
    assert answer(200, empty_refresh) == (200, 'token endpoint returned an unusable response')


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
    with CallbackServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler) as server:
        port = server.server_address[1]

        def browser():
            pool = urllib3.PoolManager()
            assert pool.request('GET', f'http://127.0.0.1:{port}/favicon.ico').status == 404
            assert pool.request('GET', f'http://127.0.0.1:{port}/callback?code=c&state=s').status == 200

        threading.Thread(target=browser, daemon=True).start()
        assert wait_for_callback(server).params == {'code': 'c', 'state': 's'}


def test_session_from_tokens():
    client = {'client_id': 'cid', 'client_redirect_uris': [loopback_redirect]}
    session = session_from_tokens(
        {'access_token': 'a', 'refresh_token': 'r', 'expires_in': 3600}, client, 'https://x/b/oauth/token')
    assert session['access_token'] == 'a'
    assert client_fields(session) == client
    assert 3500 < session['expires_at'] - time.time() <= 3600
    assert json.dumps(session)


def test_reusable_client():
    code_page = 'https://inboxtrue.com' + code_page_path
    legacy = {'client_id': 'old', 'access_token': 'a'}
    assert reusable_client(legacy, loopback_redirect) == {'client_id': 'old'}
    assert reusable_client(legacy, code_page) is None
    current = {'client_id': 'new', 'client_redirect_uris': [loopback_redirect, code_page], 'refresh_token': 'r'}
    assert reusable_client(current, code_page) == client_fields(current)
    assert reusable_client({}, loopback_redirect) is None


def test_pasted_params():
    assert pasted_params('  c0de#st4te\n') == {'code': 'c0de', 'state': 'st4te'}
    assert pasted_params('c0de') == {'code': 'c0de', 'state': ''}
