import http.server
import socket
import threading
from importlib.metadata import version

import pytest
from click.testing import CliRunner

from inboxtrue import auth, client
from inboxtrue.__main__ import cli


@pytest.mark.parametrize('command', [['credits'], ['validate', 'a@example.com'], ['login', '--no-browser'],
                                     ['login', '--code']])
def test_network_failures_are_cli_errors(command, tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    monkeypatch.setenv('INBOXTRUE_API_KEY', 'test-key')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        monkeypatch.setenv('INBOXTRUE_API_URL', f'http://127.0.0.1:{listener.getsockname()[1]}')
        result = CliRunner().invoke(cli, command)
    assert result.exit_code == 1
    assert isinstance(result.exception, SystemExit)
    assert 'Network request failed' in result.output


@pytest.mark.parametrize('payload', [b'[]', b'null', b'"unavailable"', b'<html>unavailable</html>'])
def test_non_object_error_responses_keep_http_status(payload):
    response = client.urllib3.HTTPResponse(body=payload, status=503)
    assert client.error_message(response) == 'HTTP 503'


@pytest.mark.parametrize('payload', [b'[]', b'null', b'<html>unavailable</html>'])
def test_unusable_success_responses_are_api_errors(payload, tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    monkeypatch.setenv('INBOXTRUE_API_KEY', 'test-key')

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format, *args):
            pass

    with http.server.HTTPServer(('127.0.0.1', 0), Handler) as server:
        monkeypatch.setenv('INBOXTRUE_API_URL', f'http://127.0.0.1:{server.server_port}')
        worker = threading.Thread(target=server.handle_request)
        worker.start()
        try:
            with pytest.raises(client.ApiError, match='unusable response'):
                client.credits()
        finally:
            worker.join(timeout=3)


def test_login_deadline_survives_an_incomplete_http_request(monkeypatch):
    monkeypatch.setattr(auth, 'login_timeout', 0.15)
    with auth.CallbackServer(('127.0.0.1', 0), http.server.BaseHTTPRequestHandler) as server:
        connection = socket.create_connection(server.server_address)
        connection.sendall(b'GET /callback HTTP/1.1\r\n')
        errors = []

        def wait():
            try:
                auth.wait_for_callback(server)
            except auth.AuthError as exc:
                errors.append(exc)

        worker = threading.Thread(target=wait)
        worker.start()
        try:
            worker.join(timeout=1)
            assert not worker.is_alive(), 'Incomplete request blocked the login deadline'
            assert errors and 'no answer from the browser' in str(errors[0])
        finally:
            connection.close()
            worker.join(timeout=2)


def test_version_is_available_without_credentials(tmp_path, monkeypatch):
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path))
    result = CliRunner().invoke(cli, ['--version'])
    assert result.exit_code == 0
    assert f'version {version("inboxtrue")}' in result.output
    assert not tmp_path.joinpath('inboxtrue').exists()
