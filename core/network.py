from flask import Blueprint, request
from core.utils import success, error, is_valid_ip, is_valid_domain
import socket
import requests
import os
import json

network_bp = Blueprint('network', __name__)


# -- DNS LOOKUP ----------------------------------------------------------------
@network_bp.route('/dns', methods=['POST'])
def dns_lookup():
    """Full DNS lookup for a domain."""
    data   = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return error('Provide a domain or IP')

    result = { 'target': target }

    # Resolve IP
    try:
        import dns.resolver
        import dns.reversename

        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'PTR']
        records = {}

        for rtype in record_types:
            try:
                answers = dns.resolver.resolve(target, rtype, lifetime=4)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass

        result['records'] = records

        # Reverse DNS
        try:
            rev   = dns.reversename.from_address(target)
            ptr   = dns.resolver.resolve(rev, 'PTR', lifetime=3)
            result['reverse_dns'] = [str(r) for r in ptr]
        except Exception:
            pass

    except ImportError:
        # Fallback without dnspython
        try:
            ip = socket.gethostbyname(target)
            result['records'] = { 'A': [ip] }
        except Exception as ex:
            return error(f'DNS lookup failed: {str(ex)}')

    return success(result)


# -- WHOIS ---------------------------------------------------------------------
@network_bp.route('/whois', methods=['POST'])
def whois_lookup():
    """WHOIS lookup for domain or IP."""
    data   = request.json or {}
    target = data.get('target', '').strip()
    if not target:
        return error('Provide a domain or IP')

    try:
        import whois
        w      = whois.whois(target)
        result = {}

        fields = [
            'domain_name', 'registrar', 'whois_server', 'referral_url',
            'updated_date', 'creation_date', 'expiration_date',
            'name_servers', 'status', 'emails', 'dnssec',
            'name', 'org', 'address', 'city', 'state',
            'zipcode', 'country',
        ]
        for f in fields:
            val = getattr(w, f, None)
            if val is not None:
                if hasattr(val, 'isoformat'):
                    result[f] = val.isoformat()
                elif isinstance(val, list):
                    result[f] = [str(v) for v in val]
                else:
                    result[f] = str(val)

        return success(result)
    except ImportError:
        # Fallback: use RDAP
        try:
            r    = requests.get(f'https://rdap.org/domain/{target}', timeout=8)
            data = r.json()
            result = {
                'domain':      data.get('ldhName', target),
                'status':      data.get('status', []),
                'nameservers': [ns.get('ldhName') for ns in data.get('nameservers', [])],
                'events':      [{
                    'action': e.get('eventAction'),
                    'date':   e.get('eventDate', '')[:10]
                } for e in data.get('events', [])],
            }
            return success(result)
        except Exception as ex:
            return error(f'WHOIS failed: {str(ex)}')
    except Exception as ex:
        return error(f'WHOIS error: {str(ex)}')


# -- PORT SCANNER --------------------------------------------------------------
@network_bp.route('/portscan', methods=['POST'])
def port_scan():
    """TCP port scan with banner grabbing."""
    data   = request.json or {}
    target = data.get('target', '').strip()
    default_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                     3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017]
    ports  = data.get('ports') or default_ports
    timeout = float(data.get('timeout', 0.8))

    if not target:
        return error('Provide a target')

    if len(ports) > 200:
        return error('Maximum 200 ports per scan')

    # Resolve hostname
    try:
        ip = socket.gethostbyname(target)
    except Exception:
        return error(f'Could not resolve {target}')

    open_ports = []
    for port in ports:
        try:
            port = int(port)
            s    = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                banner = ''
                try:
                    s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                    banner = s.recv(256).decode('utf-8', errors='replace').strip()[:100]
                except Exception:
                    pass
                s.close()
                open_ports.append({
                    'port':    port,
                    'service': get_service_name(port),
                    'banner':  banner,
                })
            else:
                s.close()
        except Exception:
            pass

    return success({
        'target':     target,
        'ip':         ip,
        'open_ports': open_ports,
        'total_open': len(open_ports),
    })


def get_service_name(port):
    services = {
        21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',53:'DNS',
        80:'HTTP',110:'POP3',143:'IMAP',443:'HTTPS',445:'SMB',
        3306:'MySQL',3389:'RDP',5432:'PostgreSQL',5900:'VNC',
        6379:'Redis',8080:'HTTP-Alt',8443:'HTTPS-Alt',
        8888:'Jupyter',9200:'Elasticsearch',27017:'MongoDB',
        11211:'Memcached',2181:'ZooKeeper',2379:'etcd',
    }
    return services.get(port, 'unknown')


# -- GEOLOCATION ---------------------------------------------------------------
@network_bp.route('/geoip', methods=['POST'])
def geo_ip():
    """IP geolocation lookup."""
    data = request.json or {}
    ip   = data.get('ip', '').strip()
    if not ip:
        return error('Provide an IP address')

    try:
        r    = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,message,country,regionName,'
            f'city,zip,lat,lon,timezone,isp,org,as,query,reverse',
            timeout=6
        )
        geo  = r.json()
        if geo.get('status') != 'success':
            return error(geo.get('message', 'Lookup failed'))
        return success(geo)
    except Exception as ex:
        return error(f'Geo lookup failed: {str(ex)}')


# -- ABUSEIPDB CHECK -----------------------------------------------------------
@network_bp.route('/abuseipdb', methods=['POST'])
def check_abuseipdb():
    """Check IP reputation on AbuseIPDB."""
    data    = request.json or {}
    ip      = data.get('ip', '').strip()
    api_key = os.getenv('ABUSEIPDB_API_KEY', '')

    if not ip:
        return error('Provide an IP address')
    if not api_key:
        return error('AbuseIPDB API key not configured in .env')

    try:
        headers = { 'Key': api_key, 'Accept': 'application/json' }
        params  = { 'ipAddress': ip, 'maxAgeInDays': 90, 'verbose': True }
        r       = requests.get('https://api.abuseipdb.com/api/v2/check',
                               headers=headers, params=params, timeout=8)
        return success(r.json().get('data', {}))
    except Exception as ex:
        return error(f'AbuseIPDB error: {str(ex)}')


# -- HTTP HEADER CHECKER -------------------------------------------------------
@network_bp.route('/headers', methods=['POST'])
def check_headers():
    """Fetch and analyze HTTP security headers from a URL."""
    data = request.json or {}
    url  = data.get('url', '').strip()
    if not url:
        return error('Provide a URL')
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    try:
        r = requests.get(url, timeout=8, allow_redirects=True,
                         headers={'User-Agent': 'BlackBox-Core/1.0 Security Scanner'})

        security_headers = [
            'content-security-policy',
            'strict-transport-security',
            'x-frame-options',
            'x-content-type-options',
            'x-xss-protection',
            'referrer-policy',
            'permissions-policy',
            'cross-origin-embedder-policy',
            'cross-origin-opener-policy',
            'cross-origin-resource-policy',
        ]

        all_headers = dict(r.headers)
        lower_headers = { k.lower(): v for k, v in all_headers.items() }

        analysis = []
        for sh in security_headers:
            present = sh in lower_headers
            analysis.append({
                'header':  sh,
                'present': present,
                'value':   lower_headers.get(sh, ''),
            })

        score = sum(1 for a in analysis if a['present'])

        return success({
            'url':             url,
            'status_code':     r.status_code,
            'final_url':       r.url,
            'all_headers':     all_headers,
            'security_analysis': analysis,
            'security_score':  f'{score}/{len(security_headers)}',
        })
    except Exception as ex:
        return error(f'Header check failed: {str(ex)}')


# -- SUBDOMAIN RECON (crt.sh) --------------------------------------------------
@network_bp.route('/subdomains', methods=['POST'])
def find_subdomains():
    """Find subdomains via certificate transparency logs."""
    data   = request.json or {}
    domain = data.get('domain', '').strip()
    if not domain:
        return error('Provide a domain')

    try:
        r     = requests.get(f'https://crt.sh/?q=%.{domain}&output=json', timeout=10)
        certs = r.json()
        subdomains = set()
        for entry in certs:
            for sub in entry.get('name_value', '').split('\n'):
                sub = sub.strip().lstrip('*.')
                if sub.endswith(domain) and sub != domain:
                    subdomains.add(sub)

        # Try to resolve each
        resolved = []
        for sub in list(subdomains)[:50]:  # limit to 50
            try:
                ip = socket.gethostbyname(sub)
                resolved.append({ 'subdomain': sub, 'ip': ip, 'alive': True })
            except Exception:
                resolved.append({ 'subdomain': sub, 'ip': None, 'alive': False })

        resolved.sort(key=lambda x: x['alive'], reverse=True)

        return success({
            'domain':     domain,
            'total':      len(subdomains),
            'subdomains': resolved,
        })
    except Exception as ex:
        return error(f'Subdomain recon failed: {str(ex)}')


# -- SHODAN SEARCH -------------------------------------------------------------
@network_bp.route('/shodan', methods=['POST'])
def shodan_search():
    """Search Shodan for host information."""
    data    = request.json or {}
    ip      = data.get('ip', '').strip()
    api_key = os.getenv('SHODAN_API_KEY', '')

    if not ip:
        return error('Provide an IP address')
    if not api_key:
        return error('Shodan API key not configured in .env')

    try:
        r = requests.get(
            f'https://api.shodan.io/shodan/host/{ip}?key={api_key}',
            timeout=8
        )
        if r.status_code == 404:
            return success({ 'found': False, 'message': 'No Shodan data for this IP' })
        data = r.json()
        return success({
            'found':     True,
            'ip':        data.get('ip_str'),
            'org':       data.get('org'),
            'os':        data.get('os'),
            'country':   data.get('country_name'),
            'ports':     data.get('ports', []),
            'vulns':     list(data.get('vulns', {}).keys()),
            'hostnames': data.get('hostnames', []),
            'tags':      data.get('tags', []),
        })
    except Exception as ex:
        return error(f'Shodan error: {str(ex)}')


# -- SSL CERTIFICATE INFO ------------------------------------------------------
@network_bp.route('/ssl', methods=['POST'])
def ssl_info():
    """Get SSL certificate details for a domain."""
    data   = request.json or {}
    domain = data.get('domain', '').strip()
    port   = int(data.get('port', 443))
    if not domain:
        return error('Provide a domain')

    try:
        import ssl
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(8)
        conn.connect((domain, port))
        cert = conn.getpeercert()
        conn.close()

        import datetime
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer  = dict(x[0] for x in cert.get('issuer', []))
        not_after = cert.get('notAfter', '')
        sans = [v for k, v in cert.get('subjectAltName', []) if k == 'DNS']

        try:
            expiry    = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            days_left = (expiry - datetime.datetime.utcnow()).days
        except Exception:
            days_left = None

        return success({
            'domain':      domain,
            'subject':     subject,
            'issuer':      issuer,
            'not_before':  cert.get('notBefore'),
            'not_after':   not_after,
            'days_left':   days_left,
            'expired':     days_left is not None and days_left < 0,
            'sans':        sans,
            'serial':      str(cert.get('serialNumber', '')),
            'version':     cert.get('version'),
        })
    except Exception as ex:
        return error(f'SSL check failed: {str(ex)}')
