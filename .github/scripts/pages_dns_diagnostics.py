"""Read-only DNS and HTTPS diagnostics for MathBusters, without credentials."""

import ipaddress
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen

HOSTS = ['math-busters.com', 'www.math-busters.com']
TYPES = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'CAA']
RESOLVERS = [None, '8.8.8.8', '1.1.1.1', 'ns29.domaincontrol.com', 'ns30.domaincontrol.com']
IPS = ['185.199.108.153', '185.199.109.153', '185.199.110.153', '185.199.111.153']
EXPECTED = {ipaddress.ip_address(ip) for ip in IPS}
EXPECTED.update(ipaddress.ip_address(f'2606:50c0:800{i}::153') for i in range(4))


def command(args, input_text=None):
    try:
        result = subprocess.run(args, input=input_text, text=True, capture_output=True, timeout=20)
        return {'exit_code': result.returncode, 'stdout': result.stdout.strip(), 'stderr': result.stderr.strip()}
    except subprocess.TimeoutExpired:
        return {'error': 'command timed out'}


def dns(case):
    host, kind, resolver = case
    args = ['dig', '+time=2', '+tries=1', '+noall', '+comments', '+answer']
    if resolver:
        args.append('@' + resolver)
    result = command(args + [host, kind])
    result.update(host=host, query=kind, resolver=resolver or 'runner-default')
    unexpected = []
    for line in result.get('stdout', '').splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[3] in {'A', 'AAAA'}:
            if ipaddress.ip_address(fields[4]) not in EXPECTED:
                unexpected.append({'name': fields[0], 'address': fields[4]})
    result['unexpected_addresses'] = unexpected
    return result


def doh(case):
    host, kind, provider = case
    base = 'https://dns.google/resolve' if provider == 'google' else 'https://cloudflare-dns.com/dns-query'
    url = base + '?' + urlencode({'name': host, 'type': kind})
    try:
        request = Request(url, headers={'Accept': 'application/dns-json'})
        with urlopen(request, timeout=15) as response:
            data = json.load(response)
        return {'host': host, 'query': kind, 'provider': provider, 'response': data}
    except Exception as error:
        return {'host': host, 'query': kind, 'provider': provider, 'error': str(error)}


def http(case):
    host, scheme, ip = case
    args = ['curl', '-sS', '-I', '--connect-timeout', '5', '--max-time', '12']
    if ip:
        args += ['--resolve', f'{host}:{443 if scheme == "https" else 80}:{ip}']
    args += ['--write-out', '\nremote_ip=%{remote_ip}\nhttp_code=%{http_code}\n', f'{scheme}://{host}/']
    result = command(args)
    result.update(host=host, scheme=scheme, endpoint=ip or 'runner-default')
    return result


def certificate(ip):
    result = command(['openssl', 's_client', '-connect', ip + ':443', '-servername', HOSTS[1], '-showcerts'], '')
    output = result.get('stdout', '')
    start, end = output.find('-----BEGIN CERTIFICATE-----'), output.find('-----END CERTIFICATE-----')
    if start >= 0 and end >= 0:
        pem = output[start:end + len('-----END CERTIFICATE-----')]
        result = command(['openssl', 'x509', '-noout', '-subject', '-issuer', '-dates', '-ext', 'subjectAltName'], pem)
    else:
        result = {'error': 'No certificate received', 'details': result}
    result['endpoint'] = ip
    return result


def collect(function, cases):
    with ThreadPoolExecutor(max_workers=8) as pool:
        return list(pool.map(function, cases))


report = {
    'time_utc': datetime.now(timezone.utc).isoformat(),
    'runner_nameservers': [line for line in Path('/etc/resolv.conf').read_text().splitlines() if line.startswith('nameserver')],
    'dns': collect(dns, [(host, kind, resolver) for host in HOSTS for kind in TYPES for resolver in RESOLVERS]),
    'dns_over_https': collect(doh, [(host, kind, provider) for host in HOSTS for kind in ['A', 'AAAA', 'CNAME', 'MX'] for provider in ['google', 'cloudflare']]),
    'http': collect(http, [(host, scheme, ip) for host in HOSTS for scheme in ['http', 'https'] for ip in [None] + IPS]),
    'certificates': collect(certificate, IPS),
}
Path('pages-dns-diagnostics.json').write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
