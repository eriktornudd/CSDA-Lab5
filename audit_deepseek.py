#!/usr/bin/env python3
"""
Web Security Audit Automation Script (v2)
For educational purposes only.
Only use on systems you own or have explicit written permission to test.

Key change in v2: all web checks are gated behind a service-discovery phase.
If no HTTP/HTTPS service responds, web-specific findings are NOT reported
(previously, missing-header findings were emitted even when 443 was filtered).

Usage:
    python3 audit_deepseek.py https://example.com
    python3 audit_deepseek.py https://example.com -o results --skip nikto directory_discovery
    python3 audit_deepseek.py https://example.com --only ssl_testssl security_headers
    python3 audit_deepseek.py https://example.com --config audit_config.json
    python3 audit_deepseek.py 130.208.246.173 --ports 80,443,8080
"""

import subprocess
import sys
import os
import argparse
import json
import re
import shutil
import socket
import tempfile
import html
from datetime import datetime, timezone
from urllib.parse import urlparse, urljoin


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Severity classification rules. Checked in order; first match wins.
# Pattern is case-insensitive substring match against the finding title.
SEVERITY_RULES = [
    ('Heartbleed', 'HIGH'),
    ('VULNERABLE', 'HIGH'),
    ('Dangerous HTTP method', 'HIGH'),
    ('Potentially exposed', 'HIGH'),
    ('Deprecated SSL', 'HIGH'),
    ('Weak ciphers', 'HIGH'),
    ('does not redirect to HTTPS', 'HIGH'),
    ('CORS wildcard', 'HIGH'),
    ('CORS reflects arbitrary', 'HIGH'),
    ('expired', 'HIGH'),
    ('missing Secure flag', 'MEDIUM'),
    ('missing HttpOnly flag', 'MEDIUM'),
    ('missing SameSite', 'MEDIUM'),
    ('expires in', 'MEDIUM'),
    ('discloses version', 'LOW'),
    ('not implemented', 'LOW'),
    ('not set', 'LOW'),
    ('protection missing', 'LOW'),
]

# Security headers we check for and a description of the risk if missing.
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS not implemented',
    'Content-Security-Policy':   'CSP not implemented',
    'X-Frame-Options':           'Clickjacking protection missing',
    'X-Content-Type-Options':    'MIME sniffing protection missing',
    'Referrer-Policy':           'Referrer policy not set',
    'Permissions-Policy':        'Permissions policy not set',
}

# Informational headers (not counted as strongly).
INFORMATIONAL_HEADERS = {
    'Cross-Origin-Opener-Policy':   'COOP not set',
    'Cross-Origin-Resource-Policy': 'CORP not set',
}

# Files/paths we test for accidental exposure.
SENSITIVE_PATHS = [
    '/.env', '/.env.bak', '/.git/config', '/.git/HEAD', '/.svn/entries',
    '/wp-config.php.bak', '/config.php.bak', '/backup.zip',
    '/.htaccess', '/.htpasswd', '/phpinfo.php', '/server-status',
    '/server-info', '/.DS_Store', '/web.config', '/composer.json',
    '/package.json', '/robots.txt', '/sitemap.xml',
    '/.well-known/security.txt', '/swagger.json', '/openapi.json',
]

# Candidate wordlist locations for directory brute-forcing.
WORDLIST_CANDIDATES = [
    "/snap/seclists/current/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
]

# Ports we quickly probe if the original target URL doesn't respond.
COMMON_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

# Timeout (seconds) used for a single curl probe.
PROBE_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

class WebSecurityAuditor:

    def __init__(self, target_url, output_dir="audit_results",
                 config=None, skip_checks=None, only_checks=None,
                 quiet=False, verbose=False, rate=50, ports=None):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target_url)
        self.domain     = self.parsed_url.netloc          # includes port if present
        self.hostname   = self.parsed_url.hostname        # no port
        self.output_dir = output_dir
        self.results    = {}
        self.timestamp  = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.quiet      = quiet
        self.verbose    = verbose
        self.rate       = rate
        self.skip_checks = set(skip_checks or [])
        self.only_checks = set(only_checks or [])
        self.explicit_ports = [int(p) for p in ports] if ports else None

        # Populated by run_service_discovery()
        self.services = []
        self.primary_url = self.target_url

        # Merge config over defaults.
        cfg = config or {}
        self.timeout_default  = cfg.get('timeout', 300)
        self.whatweb_aggr     = cfg.get('whatweb_aggression', 3)
        self.ffuf_wordlist    = cfg.get('ffuf_wordlist')
        self.timeout_ssltest  = cfg.get('timeout_ssl', 600)
        self.timeout_nikto    = cfg.get('timeout_nikto', 600)
        self.timeout_dirscan  = cfg.get('timeout_dirscan', 600)
        self.probe_timeout    = cfg.get('probe_timeout', PROBE_TIMEOUT)
        self.extra_ports      = cfg.get('extra_ports', [])  # list of ints

        os.makedirs(self.output_dir, exist_ok=True)
        self.available_tools = self._check_tools()

    # ------------------------------------------------------------------ utils

    def _log(self, msg, always=False):
        """Print only if not quiet (or if always=True)."""
        if not self.quiet or always:
            print(msg)

    def _vlog(self, msg):
        """Verbose-only logging."""
        if self.verbose:
            print(msg)

    def _check_tools(self):
        """Check which external tools are available on the system."""
        self._log("[*] Checking for required tools...")
        tools = {
            'whatweb': 'whatweb',
            'nmap':    'nmap',
            'nikto':   'nikto',
            'dirb':    'dirb',
            'ffuf':    'ffuf',
            'openssl': 'openssl',
            'curl':    'curl',
        }
        testssl_path = shutil.which('testssl.sh') or shutil.which('testssl')

        available = {}
        for name, cmd in tools.items():
            ok = shutil.which(cmd) is not None
            available[name] = ok
            self._log(f"    {'[+]' if ok else '[-]'} {name}"
                      + ('' if ok else ' (not installed)'))

        available['testssl'] = testssl_path is not None
        available['testssl_path'] = testssl_path
        self._log(f"    {'[+]' if testssl_path else '[-]'} testssl.sh"
                  + (f' ({testssl_path})' if testssl_path else ' (not installed)'))
        return available

    def _run_command(self, args, timeout=None, input_data=None):
        """
        Execute a command with argument list (no shell).
        Returns a dict: {success, stdout, stderr, returncode}
        """
        if timeout is None:
            timeout = self.timeout_default
        self._vlog(f"    $ {' '.join(args)}")
        try:
            result = subprocess.run(
                args,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=input_data
            )
            return {
                'success':    result.returncode == 0,
                'stdout':     result.stdout or '',
                'stderr':     result.stderr or '',
                'returncode': result.returncode,
            }
        except subprocess.TimeoutExpired:
            return {'success': False, 'stdout': '', 'stderr':
                    f'Command timed out after {timeout}s', 'returncode': -1}
        except FileNotFoundError as e:
            return {'success': False, 'stdout': '', 'stderr':
                    f'Command not found: {e}', 'returncode': -1}
        except Exception as e:
            return {'success': False, 'stdout': '', 'stderr':
                    str(e), 'returncode': -1}

    def _write(self, name, content):
        """Write a raw output file and return its path."""
        path = os.path.join(self.output_dir, f"{name}_{self.timestamp}.txt")
        with open(path, 'w', encoding='utf-8', errors='replace') as f:
            f.write(content)
        return path

    def _classify(self, text):
        """Return severity level for a finding title."""
        low = (text or '').lower()
        for pattern, level in SEVERITY_RULES:
            if pattern.lower() in low:
                return level
        return 'INFO'

    def _finding(self, title, evidence=None, url=None,
                 confidence='confirmed', check=None):
        """Build a structured finding."""
        return {
            'title':      title,
            'severity':   self._classify(title),
            'confidence': confidence,   # confirmed | tentative | heuristic
            'evidence':   evidence,
            'url':        url,
            'check':      check,
        }

    @staticmethod
    def _parse_headers(raw):
        """Parse a raw header block; return dict of lowercase -> list of values."""
        headers = {}
        for block in re.split(r'\r?\n\r?\n', raw or ''):
            for line in block.splitlines():
                if ':' in line and not line.startswith('HTTP/'):
                    k, v = line.split(':', 1)
                    headers.setdefault(k.strip().lower(), []).append(v.strip())
        return headers

    @staticmethod
    def _fast_port_check(host, port, timeout=1.5):
        """Cheap TCP connect() check to filter out closed ports quickly."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        except Exception:
            return False

    def _require_services(self, check_name):
        """Return an error dict if no web service was confirmed."""
        if not self.services:
            return {
                'error': (
                    f"No reachable web service confirmed; '{check_name}' "
                    f"skipped (this prevents false-positive findings)"
                )
            }
        return None

    # ------------------------------------------------------------- discovery

    def _probe_http(self, url, timeout=None):
        """
        Probe a URL with curl. Returns a dict if an HTTP response was
        received, else None. Captures headers, body snippet, status,
        redirect count.
        """
        if timeout is None:
            timeout = self.probe_timeout

        body_f = tempfile.NamedTemporaryFile(delete=False).name
        hdr_f  = tempfile.NamedTemporaryFile(delete=False).name
        fmt = ('%{http_code}|%{url_effective}|%{num_redirects}|'
               '%{time_total}|%{size_download}|%{content_type}')

        args = [
            'curl', '-sS', '-k', '-L',
            '-o', body_f, '-D', hdr_f,
            '-w', fmt,
            '--max-time', str(timeout),
            '-A', 'Mozilla/5.0 (compatible; WebAudit/2.0)',
            url,
        ]
        try:
            result = self._run_command(args, timeout=timeout + 5)
            headers_raw = ''
            body = ''
            try:
                if os.path.exists(hdr_f):
                    with open(hdr_f, 'r', errors='replace') as f:
                        headers_raw = f.read()
                if os.path.exists(body_f):
                    with open(body_f, 'r', errors='replace') as f:
                        body = f.read(65536)
            except OSError:
                pass

            if not result['stdout']:
                return None

            parts = result['stdout'].strip().split('|')
            if len(parts) < 6:
                return None
            try:
                code = int(parts[0])
            except ValueError:
                return None
            if code == 0:
                # No HTTP response was actually received.
                return None

            return {
                'url':          url,
                'status':       code,
                'final_url':    parts[1],
                'redirects':    int(parts[2] or 0),
                'time_total':   float(parts[3] or 0),
                'size':         int(parts[4] or 0),
                'content_type': parts[5],
                'headers_raw':  headers_raw,
                'headers':      self._parse_headers(headers_raw),
                'body_snippet': body[:4096],
                'scheme':       urlparse(url).scheme,
                'port':         urlparse(url).port or (
                    443 if urlparse(url).scheme == 'https' else 80),
                'host':         urlparse(url).hostname,
            }
        finally:
            for p in (body_f, hdr_f):
                try:
                    os.remove(p)
                except OSError:
                    pass

    def _candidate_urls(self):
        """Build an ordered list of URLs to try during discovery."""
        urls = [self.target_url]
        seen = {self.target_url}

        host = self.hostname
        tport = self.parsed_url.port or (
            443 if self.parsed_url.scheme == 'https' else 80)
        alt_scheme = 'http' if self.parsed_url.scheme == 'https' else 'https'

        # Alternate scheme on the same port.
        u = f"{alt_scheme}://{host}:{tport}"
        if u not in seen:
            urls.append(u); seen.add(u)

        ports = set(COMMON_WEB_PORTS)
        if self.explicit_ports:
            ports.update(self.explicit_ports)
        ports.update(self.extra_ports)
        ports.discard(tport)

        for p in sorted(ports):
            if not self._fast_port_check(host, p):
                continue
            for sch in ('https', 'http'):
                u = f"{sch}://{host}:{p}"
                if u not in seen:
                    urls.append(u); seen.add(u)
        return urls

    def run_service_discovery(self):
        """
        Confirm which HTTP/HTTPS services are actually reachable.
        Populates self.services and self.primary_url.
        This runs before every other check.
        """
        self._log("\n[*] Service Discovery - Probing for reachable web services")
        services = []
        candidates = self._candidate_urls()
        self._vlog(f"    candidates: {candidates}")

        for url in candidates:
            resp = self._probe_http(url)
            if resp:
                key = (resp['scheme'], resp['port'])
                if not any((s['scheme'], s['port']) == key for s in services):
                    services.append(resp)
                    self._log(f"    [+] {url} -> HTTP {resp['status']} "
                              f"({resp['content_type'] or 'no content-type'})")

        self.services = services
        if services:
            self.primary_url = services[0]['url']

        findings = []
        if not services:
            findings.append(self._finding(
                "No reachable web service found",
                evidence=f"Probed {len(candidates)} candidate URL(s) with no HTTP response",
                confidence='confirmed',
                check='service_discovery',
            ))
        else:
            # Note if the original target URL itself did not respond.
            if not any(s['url'] == self.target_url for s in services):
                findings.append(self._finding(
                    "Original target URL did not respond; audit redirected "
                    "to a discovered service",
                    evidence=f"Using {self.primary_url}",
                    url=self.primary_url,
                    confidence='confirmed',
                    check='service_discovery',
                ))

        return {
            'candidates_probed':  len(candidates),
            'confirmed_services': [
                {
                    'url':          s['url'],
                    'scheme':       s['scheme'],
                    'port':         s['port'],
                    'status':       s['status'],
                    'server':       (s['headers'].get('server') or [''])[0],
                    'content_type': s['content_type'],
                }
                for s in services
            ],
            'findings': findings,
            'summary': (f"{len(services)} reachable web service(s) confirmed"
                        if services else
                        "No reachable web service confirmed"),
        }

    # ----------------------------------------------------------------- checks

    def run_whatweb(self):
        """Identify web technologies in use."""
        self._log("\n[*] WhatWeb - Technology Identification")
        err = self._require_services('whatweb')
        if err: return err
        if not self.available_tools['whatweb']:
            return {'error': 'whatweb not installed'}

        findings = []
        output_files = []
        for svc in self.services:
            args = ['whatweb', '--color=never',
                    f'-a{self.whatweb_aggr}', svc['url']]
            result = self._run_command(args, timeout=60)
            out = result['stdout'] or result['stderr']
            safe = svc['url'].replace('://', '_').replace(':', '_').replace('/', '_')
            output_files.append(self._write(f'whatweb_{safe}', out))

        return {
            'output_file': output_files[0] if output_files else None,
            'output_files': output_files,
            'summary': 'See output files',
            'findings': findings,
        }

    def run_nmap_ssl(self):
        """Enumerate supported SSL/TLS cipher suites and versions."""
        self._log("\n[*] Nmap - SSL/TLS Cipher Enumeration")
        err = self._require_services('ssl_nmap')
        if err: return err
        if not self.available_tools['nmap']:
            return {'error': 'nmap not installed'}

        https_services = [s for s in self.services if s['scheme'] == 'https']
        if not https_services:
            return {'error': 'No HTTPS service confirmed; skipping SSL enumeration'}

        findings = []
        all_stdout = []
        first_file = None
        for svc in https_services:
            args = ['nmap', '-sV', '--script', 'ssl-enum-ciphers',
                    '-p', str(svc['port']), svc['host']]
            result = self._run_command(args, timeout=300)
            stdout = result['stdout']
            all_stdout.append(stdout)
            if first_file is None:
                first_file = self._write('nmap_ssl', stdout)

            if re.search(r'SSLv2|SSLv3', stdout):
                findings.append(self._finding(
                    "Deprecated SSL versions detected",
                    evidence=f"nmap ssl-enum-ciphers output for {svc['url']}",
                    url=svc['url'],
                ))
            if 'WEAK' in stdout or 'broken' in stdout.lower():
                findings.append(self._finding(
                    "Weak ciphers detected",
                    evidence=f"nmap ssl-enum-ciphers output for {svc['url']}",
                    url=svc['url'],
                ))

        return {
            'output_file': first_file,
            'findings': findings,
            'summary': (all_stdout[0][:800] if all_stdout else ''),
        }

    def run_testssl(self):
        """Run comprehensive SSL/TLS vulnerability tests."""
        self._log("\n[*] testssl.sh - Comprehensive SSL/TLS Scan")
        err = self._require_services('ssl_testssl')
        if err: return err
        if not self.available_tools['testssl']:
            return {'error': 'testssl.sh not installed'}

        https_services = [s for s in self.services if s['scheme'] == 'https']
        if not https_services:
            return {'error': 'No HTTPS service confirmed; skipping testssl'}

        tool = self.available_tools['testssl_path']
        findings = []
        first_file = None
        first_stdout = ''
        for svc in https_services:
            args = [tool, '--quiet', '--color', '0',
                    '--ip', 'one', f"{svc['host']}:{svc['port']}"]
            result = self._run_command(args, timeout=self.timeout_ssltest)
            content = result['stdout']
            if first_file is None:
                first_file = self._write('testssl', content)
                first_stdout = content

            if 'VULNERABLE' in content:
                findings.append(self._finding(
                    "TLS vulnerabilities reported by testssl",
                    evidence=f"See testssl report for {svc['url']}",
                    url=svc['url'],
                    confidence='confirmed',
                ))
            if 'Heartbleed' in content and 'not vulnerable' not in content.lower():
                findings.append(self._finding(
                    "Potential Heartbleed vulnerability",
                    evidence=f"testssl Heartbleed section for {svc['url']}",
                    url=svc['url'],
                    confidence='tentative',
                ))

        return {
            'output_file': first_file,
            'findings': findings,
            'summary': first_stdout[:800],
        }

    def run_openssl_check(self):
        """Inspect the SSL certificate chain and details."""
        self._log("\n[*] OpenSSL - Certificate Inspection")
        err = self._require_services('ssl_certificate')
        if err: return err
        if not self.available_tools['openssl']:
            return {'error': 'openssl not installed'}

        https_services = [s for s in self.services if s['scheme'] == 'https']
        if not https_services:
            return {'error': 'No HTTPS service confirmed'}

        findings = []
        cert_infos = {}
        first_file = None
        for svc in https_services:
            connect_args = ['openssl', 's_client', '-connect',
                            f"{svc['host']}:{svc['port']}",
                            '-servername', svc['host'], '-showcerts']
            s_client = self._run_command(connect_args, timeout=15,
                                         input_data='')
            x509 = self._run_command(['openssl', 'x509', '-noout', '-text'],
                                     input_data=s_client['stdout'], timeout=15)
            text = x509['stdout']
            if first_file is None:
                first_file = self._write('ssl_cert', text)

            cert_info = {}
            if text:
                issuer     = re.search(r'Issuer:\s*(.+)', text)
                subject    = re.search(r'Subject:\s*(.+)', text)
                not_before = re.search(r'Not Before:\s*(.+)', text)
                not_after  = re.search(r'Not After\s*:\s*(.+)', text)

                if issuer:     cert_info['issuer']      = issuer.group(1).strip()
                if subject:    cert_info['subject']     = subject.group(1).strip()
                if not_before: cert_info['valid_from']  = not_before.group(1).strip()
                if not_after:  cert_info['valid_until'] = not_after.group(1).strip()

                if (issuer and subject
                        and issuer.group(1).strip() == subject.group(1).strip()):
                    cert_info['warning'] = 'Self-signed certificate detected'
                    findings.append(self._finding(
                        'Self-signed certificate detected',
                        evidence=f"issuer == subject: {subject.group(1).strip()}",
                        url=svc['url'],
                    ))

                if not_after:
                    try:
                        from email.utils import parsedate_to_datetime
                        exp = parsedate_to_datetime(not_after.group(1).strip())
                        days = (exp - datetime.now(timezone.utc)).days
                        cert_info['days_to_expiry'] = days
                        if days < 0:
                            findings.append(self._finding(
                                f"TLS certificate expired {-days} days ago",
                                evidence=f"Not After: {not_after.group(1).strip()}",
                                url=svc['url'],
                            ))
                        elif days < 30:
                            findings.append(self._finding(
                                f"TLS certificate expires in {days} days",
                                evidence=f"Not After: {not_after.group(1).strip()}",
                                url=svc['url'],
                            ))
                    except Exception:
                        pass

            cert_infos[svc['url']] = cert_info

        # Keep compatibility with old report shape: a single cert_info dict.
        primary_info = cert_infos.get(self.primary_url) or (
            next(iter(cert_infos.values())) if cert_infos else {})

        return {
            'output_file':   first_file,
            'cert_info':     primary_info,
            'cert_info_by_service': cert_infos,
            'findings':      findings,
        }

    def run_security_headers_check(self):
        """Check for presence of common HTTP security headers."""
        self._log("\n[*] HTTP Security Headers")
        err = self._require_services('security_headers')
        if err: return err

        findings = []
        present_all, missing_all = [], []
        first_file = None
        raw_headers = ''

        for svc in self.services:
            if first_file is None:
                first_file = self._write('headers', svc['headers_raw'])
                raw_headers = svc['headers_raw']

            hdrs_lower = {k.lower(): v for k, v in svc['headers'].items()}
            is_https = svc['scheme'] == 'https'

            for header, message in SECURITY_HEADERS.items():
                if header == 'Strict-Transport-Security' and not is_https:
                    continue
                if header.lower() in hdrs_lower:
                    present_all.append({'header': header, 'url': svc['url']})
                else:
                    missing_all.append({'header': header, 'issue': message,
                                        'url': svc['url']})
                    findings.append(self._finding(
                        message,
                        evidence=f"{header} absent on {svc['url']}",
                        url=svc['url'],
                        confidence='confirmed',
                        check='security_headers',
                    ))

            for header, message in INFORMATIONAL_HEADERS.items():
                if header.lower() not in hdrs_lower:
                    findings.append(self._finding(
                        message,
                        evidence=f"{header} absent on {svc['url']}",
                        url=svc['url'],
                        confidence='confirmed',
                        check='security_headers',
                    ))

        return {
            'output_file':     first_file,
            'present_headers': [p['header'] for p in present_all],
            'missing_headers': missing_all,
            'findings':        findings,
            'raw_headers':     raw_headers,
        }

    def run_cookie_check(self):
        """Check Set-Cookie headers for missing security attributes."""
        self._log("\n[*] Cookie Security Flags")
        err = self._require_services('cookies')
        if err: return err

        findings = []
        total_cookies = 0
        first_file = None

        for svc in self.services:
            if first_file is None:
                first_file = self._write('cookies', svc['headers_raw'])

            cookies = svc['headers'].get('set-cookie', [])
            total_cookies += len(cookies)
            for cookie in cookies:
                name = cookie.split('=', 1)[0].strip()
                lower = cookie.lower()
                missing = []
                if 'secure' not in lower:
                    missing.append('Secure')
                if 'httponly' not in lower:
                    missing.append('HttpOnly')
                if 'samesite' not in lower:
                    missing.append('SameSite')
                for flag in missing:
                    findings.append(self._finding(
                        f"Cookie '{name}' missing {flag} flag",
                        evidence=cookie[:200],
                        url=svc['url'],
                        confidence='confirmed',
                        check='cookies',
                    ))

        return {
            'output_file':  first_file,
            'findings':     findings,
            'cookies_found': total_cookies,
        }

    def run_http_methods_check(self):
        """Check which HTTP methods the server advertises via OPTIONS."""
        self._log("\n[*] Allowed HTTP Methods")
        err = self._require_services('http_methods')
        if err: return err
        if not self.available_tools['curl']:
            return {'error': 'curl not installed'}

        findings, allowed = [], []
        first_file = None
        for svc in self.services:
            args = ['curl', '-sI', '-X', 'OPTIONS', '--max-time', '10',
                    '-A', 'Mozilla/5.0 (compatible; WebAudit/2.0)', svc['url']]
            result = self._run_command(args, timeout=15)
            if first_file is None:
                first_file = self._write('methods', result['stdout'])

            match = re.search(r'^Allow:\s*(.+)$', result['stdout'],
                              re.IGNORECASE | re.MULTILINE)
            if match:
                svc_allowed = [m.strip().upper()
                               for m in match.group(1).split(',')]
                allowed.extend(svc_allowed)
                for dangerous in ('TRACE', 'PUT', 'DELETE', 'CONNECT', 'PATCH'):
                    if dangerous in svc_allowed:
                        findings.append(self._finding(
                            f"Dangerous HTTP method enabled: {dangerous}",
                            evidence=f"Allow: {match.group(1).strip()}",
                            url=svc['url'],
                            confidence='confirmed',
                            check='http_methods',
                        ))

        return {
            'output_file':    first_file,
            'findings':       findings,
            'allowed_methods': sorted(set(allowed)),
        }

    def run_https_redirect_check(self):
        """Verify HTTP traffic redirects to HTTPS."""
        self._log("\n[*] HTTP to HTTPS Redirect")
        err = self._require_services('https_redirect')
        if err: return err
        if not self.available_tools['curl']:
            return {'error': 'curl not installed'}

        http_svc = next((s for s in self.services if s['scheme'] == 'http'), None)
        https_svc = next((s for s in self.services if s['scheme'] == 'https'), None)

        if not https_svc:
            return {'error': 'No HTTPS service confirmed; cannot evaluate redirect'}
        if not http_svc:
            return {'error': 'No HTTP service confirmed; cannot evaluate redirect',
                    'status': 'not_applicable'}

        findings = []
        status = 'unknown'
        out = http_svc['headers_raw']

        if http_svc['status'] in (301, 302, 307, 308):
            loc = (http_svc['headers'].get('location') or [''])[0]
            if loc.lower().startswith('https://'):
                status = 'redirects_to_https'
            else:
                status = 'redirects_elsewhere'
                findings.append(self._finding(
                    "HTTP redirects but not to HTTPS",
                    evidence=f"Location: {loc}",
                    url=http_svc['url'],
                    confidence='confirmed',
                    check='https_redirect',
                ))
        else:
            status = 'no_redirect'
            findings.append(self._finding(
                "HTTP does not redirect to HTTPS",
                evidence=f"HTTP returned {http_svc['status']} with no redirect",
                url=http_svc['url'],
                confidence='confirmed',
                check='https_redirect',
            ))

        output_file = self._write('redirect', out)
        return {'output_file': output_file, 'findings': findings, 'status': status}

    def run_info_disclosure_check(self):
        """Flag version disclosure in server headers."""
        self._log("\n[*] Information Disclosure Headers")
        err = self._require_services('info_disclosure')
        if err: return err

        findings = []
        first_file = None
        for svc in self.services:
            if first_file is None:
                first_file = self._write('disclosure', svc['headers_raw'])
            for header in ('server', 'x-powered-by', 'x-aspnet-version',
                           'x-generator', 'x-drupal-cache'):
                if header in svc['headers']:
                    value = svc['headers'][header][0]
                    if re.search(r'\d', value):
                        findings.append(self._finding(
                            f"{header.title()} discloses version: {value}",
                            evidence=f"{header}: {value}",
                            url=svc['url'],
                            confidence='confirmed',
                            check='info_disclosure',
                        ))
        return {'output_file': first_file, 'findings': findings}

    def run_cors_check(self):
        """Probe for permissive CORS configuration."""
        self._log("\n[*] CORS Configuration")
        err = self._require_services('cors')
        if err: return err

        findings = []
        first_file = None
        evil_origin = 'https://evil.example'

        for svc in self.services:
            args = ['curl', '-sS', '-k', '-i',
                    '-H', f'Origin: {evil_origin}',
                    '--max-time', '10',
                    '-A', 'Mozilla/5.0 (compatible; WebAudit/2.0)',
                    svc['url']]
            result = self._run_command(args, timeout=15)
            if first_file is None:
                first_file = self._write('cors', result['stdout'])

            hdrs = self._parse_headers(result['stdout'])
            acao = (hdrs.get('access-control-allow-origin') or [''])[0]
            acac = (hdrs.get('access-control-allow-credentials') or [''])[0].lower()

            if acao == '*' and acac == 'true':
                findings.append(self._finding(
                    "CORS wildcard origin with credentials allowed",
                    evidence=f"ACAO: {acao}, ACAC: {acac}",
                    url=svc['url'],
                    confidence='confirmed',
                    check='cors',
                ))
            elif acao == evil_origin:
                findings.append(self._finding(
                    "CORS reflects arbitrary Origin header",
                    evidence=f"ACAO reflected: {acao}",
                    url=svc['url'],
                    confidence='confirmed',
                    check='cors',
                ))
        return {'output_file': first_file, 'findings': findings}

    def run_sensitive_files_check(self):
        """Probe a small list of commonly exposed sensitive paths."""
        self._log("\n[*] Sensitive File Exposure")
        err = self._require_services('sensitive_files')
        if err: return err
        if not self.available_tools['curl']:
            return {'error': 'curl not installed'}

        findings = []
        output_file = os.path.join(self.output_dir,
                                   f"sensitive_files_{self.timestamp}.txt")
        with open(output_file, 'w') as f:
            for svc in self.services:
                base = svc['url'].rstrip('/')
                for path in SENSITIVE_PATHS:
                    url = f"{base}{path}"
                    args = ['curl', '-s', '-o', os.devnull,
                            '-w', '%{http_code}', '--max-time', '8',
                            '-A', 'Mozilla/5.0 (compatible; WebAudit/2.0)',
                            url]
                    res = self._run_command(args, timeout=12)
                    code = res['stdout'].strip()
                    f.write(f"{code}\t{url}\n")
                    if code in ('200', '301', '302', '307'):
                        findings.append(self._finding(
                            f"Potentially exposed: {path} (HTTP {code})",
                            evidence=f"{url} returned HTTP {code}",
                            url=url,
                            confidence='confirmed' if code == '200' else 'tentative',
                            check='sensitive_files',
                        ))
        return {'output_file': output_file, 'findings': findings}

    def run_nikto(self):
        """Run Nikto web server vulnerability scanner."""
        self._log("\n[*] Nikto - Web Server Scanner")
        err = self._require_services('nikto')
        if err: return err
        if not self.available_tools['nikto']:
            return {'error': 'nikto not installed'}

        findings = []
        first_file = None
        first_stdout = ''
        for svc in self.services:
            output_file = os.path.join(
                self.output_dir,
                f"nikto_{self.timestamp}_"
                f"{svc['url'].replace('://','_').replace(':','_').replace('/','_')}.txt")
            args = ['nikto', '-h', svc['url'],
                    '-o', output_file, '-Format', 'txt',
                    '-nointeractive']
            result = self._run_command(args, timeout=self.timeout_nikto)
            if first_file is None:
                first_file = output_file
                first_stdout = result['stdout']

            if os.path.exists(output_file):
                with open(output_file, 'r', errors='replace') as f:
                    content = f.read()
                for line in content.splitlines():
                    if not line.strip().startswith('+ '):
                        continue
                    low = line.lower()
                    if 'osvdb' in low or 'server leaks' in low or 'server may leak' in low:
                        findings.append(self._finding(
                            f"Nikto: {line.strip()[2:]}",
                            evidence=f"nikto report for {svc['url']}",
                            url=svc['url'],
                            confidence='confirmed',
                            check='nikto',
                        ))

        return {
            'output_file': first_file,
            'findings':    findings,
            'summary':     first_stdout[:800] or 'See output file',
        }

    def run_directory_scan(self):
        """Discover hidden directories/files using ffuf and/or dirb."""
        self._log("\n[*] Directory Discovery")
        err = self._require_services('directory_discovery')
        if err: return err

        results = {}

        # ---- ffuf (preferred) ----
        if self.available_tools['ffuf']:
            self._log("    using ffuf")
            wordlist = self.ffuf_wordlist
            if not wordlist or not os.path.exists(wordlist):
                wordlist = next((p for p in WORDLIST_CANDIDATES
                                 if os.path.exists(p)), None)

            if wordlist:
                ffuf_findings = []
                output_files = []
                for svc in self.services:
                    safe = svc['url'].replace('://','_').replace(':','_').replace('/','_')
                    output_file = os.path.join(
                        self.output_dir, f"ffuf_{self.timestamp}_{safe}.json")
                    output_files.append(output_file)
                    args = ['ffuf',
                            '-u', f"{svc['url'].rstrip('/')}/FUZZ",
                            '-w', wordlist,
                            '-o', output_file,
                            '-of', 'json',
                            '-mc', '200,204,301,302,307,401,403',
                            '-rate', str(self.rate),
                            '-s']
                    self._run_command(args, timeout=self.timeout_dirscan)

                    if os.path.exists(output_file):
                        try:
                            with open(output_file) as f:
                                data = json.load(f)
                            for hit in data.get('results', []):
                                status = hit.get('status')
                                url    = hit.get('url', '')
                                if status in (200, 301, 302, 401, 403):
                                    ffuf_findings.append(self._finding(
                                        f"Discovered: {url} (HTTP {status})",
                                        evidence=f"{hit.get('length')} bytes",
                                        url=url,
                                        confidence='confirmed',
                                        check='directory_discovery',
                                    ))
                        except Exception:
                            pass

                results['ffuf'] = {
                    'output_file': output_files[0] if output_files else None,
                    'output_files': output_files,
                    'success': True,
                    'findings': ffuf_findings,
                }
            else:
                results['ffuf'] = {'error': 'No wordlist found'}

        # ---- dirb (fallback / additional) ----
        if self.available_tools['dirb']:
            self._log("    using dirb")
            first_file = None
            for svc in self.services:
                safe = svc['url'].replace('://','_').replace(':','_').replace('/','_')
                output_file = os.path.join(
                    self.output_dir, f"dirb_{self.timestamp}_{safe}.txt")
                if first_file is None:
                    first_file = output_file
                args = ['dirb', svc['url'], '-o', output_file, '-S']
                self._run_command(args, timeout=self.timeout_dirscan)
            results['dirb'] = {
                'output_file': first_file,
                'success': True,
                'findings': [],
            }

        if not results:
            return {'error': 'Neither ffuf nor dirb is installed'}

        merged = []
        for tool, r in results.items():
            if isinstance(r, dict):
                merged.extend(r.get('findings', []))
        results['findings'] = merged
        return results

    # ----------------------------------------------------------------- report

    def generate_report(self):
        """Build JSON, text, and HTML reports."""
        report = {
            'target': self.target_url,
            'timestamp': self.timestamp,
            'domain': self.domain,
            'available_tools': {k: v for k, v in self.available_tools.items()
                                if k != 'testssl_path'},
            'services': [
                {'url': s['url'], 'scheme': s['scheme'], 'port': s['port'],
                 'status': s['status']}
                for s in self.services
            ],
            'results': self.results,
            'summary': {
                'total_checks': len(self.results),
                'web_service_reachable': bool(self.services),
                'findings_by_severity': {
                    'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []
                },
            },
        }

        # Aggregate findings (now dicts) and classify.
        for check, result in self.results.items():
            if not isinstance(result, dict):
                continue
            for f in result.get('findings', []) or []:
                if isinstance(f, dict):
                    level = f.get('severity') or self._classify(f.get('title', ''))
                    entry = {
                        'title':      f.get('title', ''),
                        'check':      f.get('check') or check,
                        'url':        f.get('url'),
                        'evidence':   f.get('evidence'),
                        'confidence': f.get('confidence', 'confirmed'),
                    }
                else:
                    level = self._classify(str(f))
                    entry = {'title': str(f), 'check': check,
                             'url': None, 'evidence': None,
                             'confidence': 'confirmed'}
                report['summary']['findings_by_severity'].setdefault(
                    level, []).append(entry)

            cert = result.get('cert_info', {})
            if isinstance(cert, dict) and 'warning' in cert:
                level = self._classify(cert['warning'])
                report['summary']['findings_by_severity'].setdefault(
                    level, []).append({
                        'title': cert['warning'],
                        'check': 'ssl_certificate',
                        'url': self.primary_url,
                        'evidence': None,
                        'confidence': 'confirmed',
                    })

        json_file = os.path.join(self.output_dir,
                                 f"security_audit_report_{self.timestamp}.json")
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        txt_file = os.path.join(self.output_dir,
                                f"security_audit_summary_{self.timestamp}.txt")
        self._write_text_report(report, txt_file)

        html_file = os.path.join(self.output_dir,
                                 f"audit_report_{self.timestamp}.html")
        self._write_html_report(report, html_file)

        return {
            'json_report':    json_file,
            'summary_report': txt_file,
            'html_report':    html_file,
            'report_data':    report,
        }

    def _write_text_report(self, report, path):
        sev = report['summary']['findings_by_severity']
        with open(path, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("WEB SECURITY AUDIT REPORT\n")
            f.write(f"Target: {report['target']}\n")
            f.write(f"Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")

            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 70 + "\n")
            f.write(f"Checks performed       : {report['summary']['total_checks']}\n")
            f.write(f"Web service reachable  : "
                    f"{'yes' if report['summary']['web_service_reachable'] else 'no'}\n")
            for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
                f.write(f"{level:<23}: {len(sev[level])}\n")
            f.write("\n")

            for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
                if not sev[level]:
                    continue
                f.write(f"{level} FINDINGS\n")
                f.write("-" * 70 + "\n")
                for item in sev[level]:
                    title = item.get('title', str(item))
                    url   = item.get('url') or ''
                    conf  = item.get('confidence', '')
                    f.write(f"  [{conf}] {title}")
                    if url:
                        f.write(f"  ({url})")
                    f.write("\n")
                f.write("\n")

            f.write("\nDETAILED RESULTS\n")
            f.write("-" * 70 + "\n")
            for check, result in self.results.items():
                f.write(f"\n[{check.upper()}]\n")
                if not isinstance(result, dict):
                    f.write(f"  {result}\n")
                    continue
                if 'error' in result:
                    f.write(f"  Error: {result['error']}\n")
                if 'output_file' in result and result['output_file']:
                    f.write(f"  Output file: {result['output_file']}\n")
                if 'summary' in result and result['summary']:
                    summary = str(result['summary']).replace('\n', ' ')
                    f.write(f"  Summary: {summary[:250]}...\n")

    def _write_html_report(self, report, path):
        sev = report['summary']['findings_by_severity']
        colors = {'HIGH': '#d32f2f', 'MEDIUM': '#f57c00',
                  'LOW': '#fbc02d', 'INFO': '#0288d1'}

        e = html.escape

        parts = [
            "<!DOCTYPE html>",
            "<html><head><meta charset='utf-8'>",
            f"<title>Audit Report - {e(report['target'])}</title>",
            "<style>",
            "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;",
            "max-width:960px;margin:2em auto;padding:0 1em;color:#222;}",
            "h1{border-bottom:3px solid #333;padding-bottom:8px;}",
            "h2{margin-top:1.6em;color:#333;}",
            ".meta{color:#666;font-size:.9em;}",
            ".badge{display:inline-block;padding:2px 10px;border-radius:12px;",
            "color:#fff;font-weight:600;font-size:.8em;margin-right:8px;}",
            ".check{border:1px solid #e0e0e0;border-radius:6px;",
            "padding:10px 14px;margin:10px 0;background:#fafafa;}",
            ".check code{background:#eef;padding:1px 5px;border-radius:3px;",
            "font-size:.85em;}",
            ".none{color:#888;font-style:italic;}",
            ".conf{color:#888;font-size:.85em;margin-left:6px;}",
            ".ev{color:#555;font-size:.9em;display:block;margin-left:16px;}",
            "</style></head><body>",
            f"<h1>Security Audit Report</h1>",
            f"<p class='meta'><b>Target:</b> {e(report['target'])}<br>",
            f"<b>Web service reachable:</b> "
            f"{'yes' if report['summary']['web_service_reachable'] else 'no'}<br>",
            f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        ]

        parts.append("<h2>Executive Summary</h2>")
        parts.append("<table style='border-collapse:collapse'>")
        for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
            parts.append(
                f"<tr><td><span class='badge' style='background:{colors[level]}'>"
                f"{level}</span></td><td>{len(sev[level])} finding(s)</td></tr>")
        parts.append("</table>")

        for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
            parts.append(f"<h2>{level} Findings</h2>")
            if not sev[level]:
                parts.append("<p class='none'>None</p>")
                continue
            parts.append("<ul>")
            for item in sev[level]:
                title = e(item.get('title', str(item)))
                url   = item.get('url') or ''
                ev    = item.get('evidence') or ''
                conf  = item.get('confidence', '')
                parts.append(f"<li>{title}")
                if conf:
                    parts.append(f"<span class='conf'>[{e(conf)}]</span>")
                if ev:
                    parts.append(f"<span class='ev'>{e(str(ev))}</span>")
                if url:
                    parts.append(f"<span class='ev'><code>{e(url)}</code></span>")
                parts.append("</li>")
            parts.append("</ul>")

        parts.append("<h2>Confirmed Services</h2>")
        if not report['services']:
            parts.append("<p class='none'>No reachable web service confirmed.</p>")
        else:
            parts.append("<ul>")
            for svc in report['services']:
                parts.append(f"<li><code>{e(svc['url'])}</code> "
                             f"(HTTP {svc['status']})</li>")
            parts.append("</ul>")

        parts.append("<h2>Detailed Results</h2>")
        for check, result in self.results.items():
            parts.append(f"<div class='check'><b>{e(check)}</b><br>")
            if not isinstance(result, dict):
                parts.append(f"{e(str(result))}</div>")
                continue
            if 'error' in result:
                parts.append(f"<i>Error:</i> {e(str(result['error']))}<br>")
            if 'output_file' in result and result['output_file']:
                parts.append(f"<i>Output:</i> <code>{e(str(result['output_file']))}</code><br>")
            if 'summary' in result and result['summary']:
                s = str(result['summary'])[:300].replace('\n', ' ')
                parts.append(f"<i>Summary:</i> {e(s)}...")
            parts.append("</div>")

        parts.append("</body></html>")

        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(parts))

    # ------------------------------------------------------------------ driver

    def run_full_audit(self):
        # Discovery is ALWAYS run first, and is not skippable, because every
        # subsequent web check depends on it.
        self._log("=" * 70, always=True)
        self._log(f"STARTING SECURITY AUDIT FOR: {self.target_url}", always=True)
        self._log(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", always=True)
        self._log("=" * 70, always=True)

        try:
            self.results['service_discovery'] = self.run_service_discovery()
        except Exception as e:
            self.results['service_discovery'] = {'error': f'Unhandled exception: {e}'}
            self._log(f"[-] Error in service_discovery: {e}", always=True)

        all_checks = [
            ('whatweb',             self.run_whatweb),
            ('ssl_nmap',            self.run_nmap_ssl),
            ('ssl_testssl',         self.run_testssl),
            ('ssl_certificate',     self.run_openssl_check),
            ('security_headers',    self.run_security_headers_check),
            ('cookies',             self.run_cookie_check),
            ('http_methods',        self.run_http_methods_check),
            ('https_redirect',      self.run_https_redirect_check),
            ('info_disclosure',     self.run_info_disclosure_check),
            ('cors',                self.run_cors_check),
            ('sensitive_files',     self.run_sensitive_files_check),
            ('nikto',               self.run_nikto),
            ('directory_discovery', self.run_directory_scan),
        ]

        if self.only_checks:
            checks = [(n, fn) for n, fn in all_checks if n in self.only_checks]
        else:
            checks = [(n, fn) for n, fn in all_checks
                      if n not in self.skip_checks]

        self._log(f"\nChecks to run: {', '.join(n for n, _ in checks)}", always=True)

        for name, fn in checks:
            try:
                self.results[name] = fn()
            except KeyboardInterrupt:
                raise
            except Exception as e:
                self.results[name] = {'error': f'Unhandled exception: {e}'}
                self._log(f"[-] Error in {name}: {e}", always=True)

        self._log("\n[*] Generating reports...")
        report = self.generate_report()

        self._log("\n" + "=" * 70, always=True)
        self._log("AUDIT COMPLETE", always=True)
        self._log("=" * 70, always=True)
        self._log(f"JSON report : {report['json_report']}", always=True)
        self._log(f"Text report : {report['summary_report']}", always=True)
        self._log(f"HTML report : {report['html_report']}", always=True)

        sev = report['report_data']['summary']['findings_by_severity']
        self._log("\nFindings by severity:", always=True)
        for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
            self._log(f"  {level:<7}: {len(sev[level])}", always=True)

        return report


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def load_config(path):
    if not path:
        return {}
    if not os.path.exists(path):
        print(f"[!] Config file not found: {path}")
        sys.exit(2)
    with open(path) as f:
        return json.load(f)


def parse_args():
    parser = argparse.ArgumentParser(
        description='Web Security Audit Automation Tool (educational).',
        epilog='Example: python3 audit_deepseek.py https://example.com -o results'
    )
    parser.add_argument('target',
                        help='Target URL or host (e.g., https://example.com)')
    parser.add_argument('-o', '--output', default='audit_results',
                        help='Output directory (default: audit_results)')
    parser.add_argument('-c', '--config', default=None,
                        help='Path to JSON config file')
    parser.add_argument('--skip', nargs='*', default=[],
                        help='Names of checks to skip')
    parser.add_argument('--only', nargs='*', default=[],
                        help='Run only these checks')
    parser.add_argument('--ports', default=None,
                        help='Comma-separated extra ports to probe during '
                             'discovery (e.g., 80,443,8080)')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Only print final summary')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print each command being run')
    parser.add_argument('--rate', type=int, default=50,
                        help='ffuf request rate (requests/sec, default 50)')
    return parser.parse_args()


def main():
    args = parse_args()

    if not args.target.startswith(('http://', 'https://')):
        args.target = 'https://' + args.target

    config = load_config(args.config)

    print("\n" + "!" * 70)
    print("WARNING: Only use this tool on systems you own or have")
    print("explicit written permission to test. Unauthorized scanning")
    print("is illegal and unethical.")
    print("!" * 70 + "\n")

    ports = None
    if args.ports:
        ports = [p.strip() for p in args.ports.split(',') if p.strip()]

    auditor = WebSecurityAuditor(
        target_url=args.target,
        output_dir=args.output,
        config=config,
        skip_checks=args.skip,
        only_checks=args.only,
        quiet=args.quiet,
        verbose=args.verbose,
        rate=args.rate,
        ports=ports,
    )

    try:
        auditor.run_full_audit()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Partial results saved in",
              args.output)
        sys.exit(130)


if __name__ == '__main__':
    main()