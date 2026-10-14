import urllib3

from inboxtrue import auth, config


class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def pool_manager() -> urllib3.PoolManager:
    # Validations wait on remote mail servers for up to the requested timeout (max 90s).
    return urllib3.PoolManager(timeout=urllib3.Timeout(connect=10, read=120), retries=False)


def error_message(resp: urllib3.BaseHTTPResponse) -> str:
    try:
        body = resp.json()
    except ValueError:
        return f'HTTP {resp.status}'
    if not isinstance(body, dict):
        return f'HTTP {resp.status}'
    return body.get('msg') or body.get('error_description') or body.get('error') or f'HTTP {resp.status}'


def api_get(path: str, **params: object) -> dict:
    '''GET an API path with the configured credential: INBOXTRUE_API_KEY when set, otherwise the OAuth session.'''
    url = config.api_url()
    fields = {k: str(v) for k, v in params.items() if v is not None}
    key = config.api_key()
    token = key or auth.access_token(url)
    pool = pool_manager()
    resp = pool.request('GET', f'{url}{path}', fields=fields, headers={'Authorization': f'Bearer {token}'})
    if resp.status == 401 and key is None:
        # The access token may have been revoked or rotated server-side before its local expiry.
        token = auth.access_token(url, force_refresh=True)
        resp = pool.request('GET', f'{url}{path}', fields=fields, headers={'Authorization': f'Bearer {token}'})
    if resp.status != 200:
        raise ApiError(resp.status, error_message(resp))
    try:
        body = resp.json()
    except ValueError as exc:
        raise ApiError(resp.status, 'API returned an unusable response; try again shortly') from exc
    if not isinstance(body, dict):
        raise ApiError(resp.status, 'API returned an unusable response; try again shortly')
    return body


def validate(email: str, timeout: int) -> dict:
    return api_get('/v1/email/validate', email=email, timeout=timeout)


def credits() -> dict:
    return api_get('/v1/credits')
