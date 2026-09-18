#!/usr/bin/env python3
"""
Web Security Audit Automation Script (v6)
For educational purposes only.
Only use on systems you own or have explicit written permission to test.

What it does
------------
Discovers reachable HTTP/HTTPS services, then runs a set of targeted,
low-noise checks: HTTP security headers, cookie flags, CORS, HTTP methods,
TLS configuration, sensitive file exposure, HTML content analysis across
discovered pages, and optional external tools (whatweb, nikto, nmap, ffuf,
dirb, testssl). Output is JSON + text + HTML, written to a per-run folder.

Design principles
-----------------
* Reachability-gated: no web finding is reported unless a real HTTP response
  was received during service discovery.
* Evidence-based: every finding carries a URL, confidence, and evidence.
* Content-length aware: a 200 with 0 bytes is not treated as an exposure.
* Tool-agnostic: each external tool is optional; missing tools are skipped.

Usage
-----
    python3 audit_deepseek.py https://example.com
    python3 audit_deepseek.py example.com --ports 80,443,8080
    python3 audit_deepseek.py https://example.com -o results --skip nikto directory_discovery
    python3 audit_deepseek.py https://example.com --only security_headers cookies
    python3 audit_deepseek.py https://example.com --flat
"""

import argparse
import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Fallback classifier for ad-hoc finding titles (e.g. lines parsed out of
# external tool output). Structured findings pass severity explicitly.
SEVERITY_RULES = [
    ('Heartbleed', 'HIGH'),
    ('VULNERABLE', 'HIGH'),
    ('Dangerous HTTP method', 'HIGH'),
    ('Deprecated SSL', 'HIGH'),
    ('Weak ciphers', 'HIGH'),
    ('does not redirect to HTTPS', 'HIGH'),
    ('expired', 'HIGH'),
    ('XSS payload', 'HIGH'),
    ('admin login', 'MEDIUM'),
    ('config.php', 'MEDIUM'),
    ('config file', 'MEDIUM'),
    ('Server error on path', 'MEDIUM'),
    ('without the httponly', 'MEDIUM'),
    ('POST form without CSRF', 'MEDIUM'),
    ('missing Secure flag', 'MEDIUM'),
    ('missing HttpOnly flag', 'MEDIUM'),
    ('missing SameSite', 'MEDIUM'),
    ('DEBUG', 'LOW'),
    ('anti-clickjacking', 'LOW'),
    ('discloses version', 'LOW'),
    ('not implemented', 'LOW'),
    ('not set', 'LOW'),
    ('protection missing', 'LOW'),
]

# Security headers to check, mapped to the risk description if missing.
# HSTS is only checked over HTTPS (see run_security_headers_check).
SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS not implemented',
    'Content-Security-Policy':   'CSP not implemented',
    'X-Frame-Options':           'Clickjacking protection missing',
    'X-Content-Type-Options':    'MIME sniffing protection missing',
    'Referrer-Policy':           'Referrer policy not set',
    'Permissions-Policy':        'Permissions policy not set',
}

# Additional headers reported at INFO level if absent.
INFORMATIONAL_HEADERS = {
    'Cross-Origin-Opener-Policy':   'COOP not set',
    'Cross-Origin-Resource-Policy': 'CORP not set',
}

# Paths probed for accidental exposure or misconfiguration. Generic set.
SENSITIVE_PATHS = [
    # Environment and version control
    '/.env', '/.env.bak', '/.env.local', '/.env.production',
    '/.git/config', '/.git/HEAD', '/.gitignore', '/.svn/entries',
    # PHP configs
    '/config.php', '/config.inc.php', '/config.php.bak', '/config.php~',
    '/config.old', '/config.sample.php', '/configuration.php',
    '/includes/config.php', '/includes/db.php', '/includes/database.php',
    '/includes/config.inc.php', '/db.php', '/database.php',
    '/wp-config.php', '/wp-config.php.bak', '/settings.php',
    # Backups
    '/backup.zip', '/backup.tar.gz', '/backup.sql', '/dump.sql',
    '/db.sql', '/database.sql',
    # Server and platform
    '/.htaccess', '/.htpasswd', '/server-status', '/server-info',
    '/phpinfo.php', '/info.php', '/test.php', '/.DS_Store',
    '/web.config', '/composer.json', '/composer.lock',
    '/package.json', '/package-lock.json', '/.editorconfig',
    # Metadata
    '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
    '/swagger.json', '/openapi.json', '/api-docs',
    # Directories whose presence is informative
    '/uploads/', '/upload/', '/files/', '/tmp/',
]

# Common wordlist locations for directory discovery. First existing wins.
WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/snap/seclists/current/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]

# Ports probed when the target URL itself doesn't respond.
COMMON_WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]

# Fallback paths for multi-page analysis when no links are discovered.
FALLBACK_PAGE_PATHS = [
    '/login', '/login.php', '/signin',
    '/register', '/register.php', '/signup',
    '/admin', '/admin/', '/dashboard', '/account',
]

# How many bytes of a response body to keep for analysis.
BODY_SNIPPET_SIZE = 16384

# Default per-probe timeout (seconds).
PROBE_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_path_component(text):
    """Make a string safe to use as a single path component."""
    if not text:
        return 'unknown'
    if '://' in text:
        text = text.split('://', 1)[1]
    text = text.split('/', 1)[0]
    text = re.sub(r'[^A-Za-z0-9._-]+', '_', text)
    return (text.strip('._-') or 'unknown')[:80]


def _service_tag(url):
    """Short filesystem-safe tag for a service URL."""
    return (url.replace('://', '_').replace(':', '_').replace('/', '_'))[:120]


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

class WebSecurityAuditor:

    def __init__(self, target_url, output_dir="audit_results",
                 config=None, skip_checks=None, only_checks=None,
                 quiet=False, verbose=False, rate=50, ports=None,
                 flat_output=False):
        # Target
        self.target_url = target_url.rstrip('/')
        parsed = urlparse(self.target_url)
        self.hostname = parsed.hostname
        self.domain = parsed.netloc
        self.explicit_ports = [int(p) for p in ports] if ports else None

        # Populated during the run
        self.services = []              # confirmed HTTP/HTTPS services
        self.primary_url = self.target_url
        self.results = {}               # check name -> result dict

        # Config
        cfg = config or {}
        self.timeout_default = cfg.get('timeout', 300)
        self.timeout_ssl = cfg.get('timeout_ssl', 600)
        self.timeout_nikto = cfg.get('timeout_nikto', 600)
        self.timeout_dirscan = cfg.get('timeout_dirscan', 600)
        self.probe_timeout = cfg.get('probe_timeout', PROBE_TIMEOUT)
        self.ffuf_wordlist = cfg.get('ffuf_wordlist')
        self.extra_ports = cfg.get('extra_ports', [])

        self.quiet = quiet
        self.verbose = verbose
        self.rate = rate
        self.skip_checks = set(skip_checks or [])
        self.only_checks = set(only_checks or [])

        # Timestamp and per-run output folder
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.abspath(output_dir)
        if flat_output:
            self.output_dir = base
        else:
            run_label = f"run_{self.timestamp}_{_sanitize_path_component(self.domain)}"
            self.output_dir = os.path.join(base, run_label)
        os.makedirs(self.output_dir, exist_ok=True)

        # Tool availability
        self.available_tools = self._check_tools()

    # ------------------------------------------------------------- logging

    def _log(self, msg, always=False):
        if always or not self.quiet:
            print(msg)

    def _vlog(self, msg):
        if self.verbose:
            print(msg)

    # --------------------------------------------------------------- tools

    def _check_tools(self):
        self._log("[*] Checking for required tools...")
        tools = ['whatweb', 'nmap', 'nikto', 'dirb', 'ffuf', 'openssl', 'curl']
        available = {}
        for tool in tools:
            available[tool] = shutil.which(tool) is not None
            mark = '[+]' if available[tool] else '[-]'
            note = '' if available[tool] else ' (not installed)'
            self._log(f"    {mark} {tool}{note}")

        testssl_path = shutil.which('testssl.sh') or shutil.which('testssl')
        available['testssl'] = testssl_path is not None
        available['testssl_path'] = testssl_path
        mark = '[+]' if testssl_path else '[-]'
        note = f' ({testssl_path})' if testssl_path else ' (not installed)'
        self._log(f"    {mark} testssl.sh{note}")
        return available

    def _preflight(self, check_name, required_tool=None):
        """Return an error result dict if preconditions fail, else None."""
        if not self.services:
            return {'error': (
                f"No reachable web service confirmed; '{check_name}' skipped "
                f"(this prevents false-positive findings)"
            )}
        if required_tool and not self.available_tools.get(required_tool):
            return {'error': f'{required_tool} not installed'}
        return None

    # ---------------------------------------------------------- execution

    def _run_command(self, args, timeout=None, input_data=None):
        """Run a command without a shell; never raises."""
        if timeout is None:
            timeout = self.timeout_default
        self._vlog(f"    $ {' '.join(args)}")
        try:
            p = subprocess.run(args, capture_output=True, text=True,
                               timeout=timeout, input=input_data)
            return {'success': p.returncode == 0, 'stdout': p.stdout or '',
                    'stderr': p.stderr or '', 'returncode': p.returncode}
        except subprocess.TimeoutExpired:
            return {'success': False, 'stdout': '', 'returncode': -1,
                    'stderr': f'Command timed out after {timeout}s'}
        except FileNotFoundError as e:
            return {'success': False, 'stdout': '', 'returncode': -1,
                    'stderr': f'Command not found: {e}'}
        except Exception as e:
            return {'success': False, 'stdout': '', 'returncode': -1,
                    'stderr': str(e)}

    def _write(self, name, content):
        """Write a text file into the current run folder, return its path."""
        path = os.path.join(self.output_dir, f"{name}.txt")
        with open(path, 'w', encoding='utf-8', errors='replace') as f:
            f.write(content)
        return path

    # ---------------------------------------------------------- findings

    def _classify(self, text):
        """Best-effort severity for an ad-hoc title."""
        low = (text or '').lower()
        for pattern, level in SEVERITY_RULES:
            if pattern.lower() in low:
                return level
        return 'INFO'

    def _finding(self, title, severity=None, evidence=None, url=None,
                 confidence='confirmed', check=None):
        return {
            'title':      title,
            'severity':   severity or self._classify(title),
            'confidence': confidence,
            'evidence':   evidence,
            'url':        url,
            'check':      check,
        }

    @staticmethod
    def _parse_headers(raw):
        """Return {lowercase_name: [values]} from a raw header block."""
        headers = {}
        for block in re.split(r'\r?\n\r?\n', raw or ''):
            for line in block.splitlines():
                if ':' in line and not line.startswith('HTTP/'):
                    k, v = line.split(':', 1)
                    headers.setdefault(k.strip().lower(), []).append(v.strip())
        return headers

    # ------------------------------------------------------------- HTTP

    @staticmethod
    def _fast_port_check(host, port, timeout=1.5):
        """Cheap TCP connect() check to filter obviously closed ports."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        except Exception:
            return False

    def _probe_http(self, url, timeout=None):
        """Probe url with curl; return a dict on any HTTP response, else None."""
        if timeout is None:
            timeout = self.probe_timeout

        body_f = tempfile.NamedTemporaryFile(delete=False).name
        hdr_f = tempfile.NamedTemporaryFile(delete=False).name
        fmt = ('%{http_code}|%{url_effective}|%{num_redirects}|'
               '%{time_total}|%{size_download}|%{content_type}')

        args = [
            'curl', '-sS', '-k', '-L',
            '-o', body_f, '-D', hdr_f, '-w', fmt,
            '--max-time', str(timeout),
            '-A', 'Mozilla/5.0 (compatible; WebAudit/6.0)',
            url,
        ]
        try:
            result = self._run_command(args, timeout=timeout + 5)
            headers_raw, body = '', ''
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
                'body_snippet': body[:BODY_SNIPPET_SIZE],
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

    # --------------------------------------------------------- discovery

    def _candidate_urls(self):
        """Ordered URLs to try during service discovery."""
        urls = [self.target_url]
        seen = {self.target_url}
        host = self.hostname
        tport = urlparse(self.target_url).port or (
            443 if self.target_url.startswith('https://') else 80)
        alt_scheme = 'http' if self.target_url.startswith('https://') else 'https'

        alt = f"{alt_scheme}://{host}:{tport}"
        if alt not in seen:
            urls.append(alt); seen.add(alt)

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
        """Confirm which HTTP/HTTPS services are reachable.

        Sets self.services and self.primary_url. Must run before every other
        check; downstream checks are gated on self.services being non-empty.
        """
        self._log("\n[*] Service Discovery")
        candidates = self._candidate_urls()
        self._vlog(f"    candidates: {candidates}")

        seen_keys = set()
        for url in candidates:
            resp = self._probe_http(url)
            if not resp:
                continue
            key = (resp['scheme'], resp['port'])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            self.services.append(resp)
            self._log(f"    [+] {url} -> HTTP {resp['status']} "
                      f"({resp['content_type'] or 'no content-type'})")

        if self.services:
            self.primary_url = self.services[0]['url']

        findings = []
        if not self.services:
            findings.append(self._finding(
                "No reachable web service found",
                severity='INFO',
                evidence=f"Probed {len(candidates)} candidate URL(s)",
                confidence='confirmed',
                check='service_discovery'))
        elif not any(s['url'] == self.target_url for s in self.services):
            findings.append(self._finding(
                "Original target URL did not respond; audit redirected to a "
                "discovered service",
                severity='INFO',
                evidence=f"Using {self.primary_url}",
                url=self.primary_url,
                confidence='confirmed',
                check='service_discovery'))

        return {
            'candidates_probed': len(candidates),
            'confirmed_services': [
                {'url': s['url'], 'scheme': s['scheme'], 'port': s['port'],
                 'status': s['status'],
                 'server': (s['headers'].get('server') or [''])[0],
                 'content_type': s['content_type']}
                for s in self.services
            ],
            'findings': findings,
            'summary': (f"{len(self.services)} reachable web service(s) confirmed"
                        if self.services else "No reachable web service confirmed"),
        }

    # -------------------------------------------------------- HTML analysis

    def _analyze_html(self, url, body, check_name):
        """Parse one page's HTML and return a list of structured findings."""
        findings = []
        if not body:
            return findings

        # <title>
        for m in re.finditer(r'<title[^>]*>(.*?)</title>', body,
                             re.IGNORECASE | re.DOTALL):
            title = re.sub(r'\s+', ' ', m.group(1)).strip()[:200]
            if title:
                findings.append(self._finding(
                    f"Page title: {title}", severity='INFO',
                    evidence=url, url=url, check=check_name))

        # Forms, with a CSRF audit for POST forms
        for fm in re.finditer(r'<form\b([^>]*)>(.*?)</form>', body,
                              re.IGNORECASE | re.DOTALL):
            attrs, inner = fm.group(1), fm.group(2)
            action_m = re.search(r'action\s*=\s*["\']([^"\']*)["\']',
                                 attrs, re.IGNORECASE)
            method_m = re.search(r'method\s*=\s*["\']([^"\']*)["\']',
                                 attrs, re.IGNORECASE)
            action = action_m.group(1) if action_m else '(same page)'
            method = (method_m.group(1) if method_m else 'GET').upper()

            findings.append(self._finding(
                f"Form: action={action} method={method}", severity='INFO',
                evidence=url, url=url, check=check_name))

            if method == 'POST':
                has_csrf = bool(re.search(
                    r'<input[^>]*\bname\s*=\s*["\'][^"\']*csrf[^"\']*["\']',
                    inner, re.IGNORECASE))
                if not has_csrf:
                    findings.append(self._finding(
                        f"POST form without CSRF token (action={action})",
                        severity='MEDIUM',
                        evidence=f"No csrf hidden input in form on {url}",
                        url=url, confidence='tentative',
                        check=check_name))

        # Input fields (informational, grouped)
        inputs = sorted({m.group(1) for m in re.finditer(
            r'<input\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']',
            body, re.IGNORECASE)})
        if inputs:
            findings.append(self._finding(
                f"Input fields: {', '.join(inputs)}", severity='INFO',
                evidence=url, url=url, check=check_name))

        # <script src>
        for m in re.finditer(r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']',
                             body, re.IGNORECASE):
            findings.append(self._finding(
                f"Script loaded: {m.group(1)}", severity='INFO',
                evidence=url, url=url, check=check_name))

        # Interesting <a href> links
        hrefs = {m.group(1) for m in re.finditer(
            r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\']', body, re.IGNORECASE)}
        interesting = sorted(
            h for h in hrefs
            if re.search(r'\.(php|asp|aspx|jsp|cgi|pl)\b', h, re.IGNORECASE)
            or '?' in h or '=' in h)
        if interesting:
            preview = ', '.join(interesting[:10])
            more = '' if len(interesting) <= 10 else f' (+{len(interesting)-10} more)'
            findings.append(self._finding(
                f"Interesting links ({len(interesting)}): {preview}{more}",
                severity='INFO', evidence=url, url=url, check=check_name))

        # Emails
        emails = sorted({e for e in re.findall(
            r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}', body)
            if not e.lower().endswith(('.png', '.jpg', '.gif', '.css', '.js'))})
        if emails:
            findings.append(self._finding(
                f"Email addresses found: {', '.join(emails[:5])}",
                severity='INFO', evidence=url, url=url,
                confidence='tentative', check=check_name))

        # HTML comments (may contain stale debug info)
        comments = [re.sub(r'\s+', ' ', c).strip()
                    for c in re.findall(r'<!--(.*?)-->', body, re.DOTALL)]
        comments = [c for c in comments if len(c) >= 10]
        if comments:
            findings.append(self._finding(
                f"HTML comments present ({len(comments)})", severity='INFO',
                evidence=' | '.join(comments[:3])[:400],
                url=url, check=check_name))

        # Unescaped <script> with alert()/document.cookie -> potential XSS.
        # Properly escaped payloads appear as &lt;script&gt; and won't match.
        if (re.search(r'<script[^>]*>\s*(?:alert|confirm|prompt)\s*\(',
                      body, re.IGNORECASE)
                or re.search(r'<script[^>]*>\s*[^<]*document\.cookie',
                             body, re.IGNORECASE)):
            findings.append(self._finding(
                "Potential stored/reflected XSS payload in HTML body",
                severity='HIGH',
                evidence="Unescaped <script> with alert()/document.cookie",
                url=url, confidence='tentative', check=check_name))

        return findings

    def _discover_pages(self, svc, cap=15):
        """Same-origin URLs worth analyzing, derived from svc's root page."""
        root = svc['url'].rstrip('/')
        body = svc.get('body_snippet') or ''
        hrefs = re.findall(r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\']',
                           body, re.IGNORECASE)

        asset_re = re.compile(
            r'\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|zip|tar|gz|mp4|webm)'
            r'(\?|$)', re.IGNORECASE)

        urls, seen = [], {root, root + '/'}
        for h in hrefs:
            if h.startswith(('mailto:', 'javascript:', 'tel:', '#')):
                continue
            if h.startswith(('http://', 'https://')):
                if not h.startswith(root):
                    continue
                full = h
            elif h.startswith('/'):
                full = root + h
            else:
                full = root + '/' + h
            full = full.split('#', 1)[0]
            if asset_re.search(full) or full in seen:
                continue
            seen.add(full)
            urls.append(full)

        # Prioritize auth/admin paths first.
        priority = ('login', 'signin', 'register', 'signup', 'admin',
                    'dashboard', 'account', 'profile')
        urls.sort(key=lambda u: 0 if any(k in u.lower() for k in priority) else 1)

        # If nothing discovered, fall back to a small generic list.
        if not urls:
            urls = [root + p for p in FALLBACK_PAGE_PATHS]

        return urls[:cap]

    # ------------------------------------------------------------- checks

    def run_body_analysis_check(self):
        """Parse the HTML of each confirmed service's root page."""
        self._log("\n[*] Body Content Analysis")
        err = self._preflight('body_analysis')
        if err: return err

        findings, first_file = [], None
        for svc in self.services:
            body = svc.get('body_snippet') or ''
            if not body:
                continue
            if first_file is None:
                first_file = self._write(f'body_{_service_tag(svc["url"])}', body)
            findings.extend(self._analyze_html(svc['url'], body, 'body_analysis'))
        return {'output_file': first_file, 'findings': findings}

    def run_page_analysis_check(self):
        """Fetch discovered sub-pages and run the HTML analyzer on each.

        Paths come from links on the root page (same-origin, non-asset),
        with auth/admin paths prioritized. Falls back to a short generic
        list if the root page contains no usable links.
        """
        self._log("\n[*] Multi-Page Content Analysis")
        err = self._preflight('page_analysis')
        if err: return err

        findings, first_file = [], None
        pages_fetched = []

        for svc in self.services:
            for url in self._discover_pages(svc):
                resp = self._probe_http(url)
                if not resp:
                    continue
                pages_fetched.append({'url': url, 'status': resp['status']})
                body = resp.get('body_snippet') or ''
                if first_file is None:
                    first_file = self._write(f'page_{_service_tag(url)}', body)
                findings.extend(self._analyze_html(url, body, 'page_analysis'))

        return {
            'output_file': first_file,
            'pages_fetched': pages_fetched,
            'findings': findings,
        }

    def run_security_headers_check(self):
        self._log("\n[*] HTTP Security Headers")
        err = self._preflight('security_headers')
        if err: return err

        findings, present_all, missing_all = [], [], []
        first_file, raw_headers = None, ''

        for svc in self.services:
            if first_file is None:
                first_file = self._write('headers', svc['headers_raw'])
                raw_headers = svc['headers_raw']

            hdrs = {k.lower(): v for k, v in svc['headers'].items()}
            is_https = svc['scheme'] == 'https'

            for header, message in SECURITY_HEADERS.items():
                if header == 'Strict-Transport-Security' and not is_https:
                    continue
                if header.lower() in hdrs:
                    present_all.append({'header': header, 'url': svc['url']})
                else:
                    missing_all.append({'header': header, 'issue': message,
                                        'url': svc['url']})
                    findings.append(self._finding(
                        message, severity='LOW',
                        evidence=f"{header} absent on {svc['url']}",
                        url=svc['url'], check='security_headers'))

            for header, message in INFORMATIONAL_HEADERS.items():
                if header.lower() not in hdrs:
                    findings.append(self._finding(
                        message, severity='LOW',
                        evidence=f"{header} absent on {svc['url']}",
                        url=svc['url'], check='security_headers'))

        return {
            'output_file': first_file,
            'present_headers': [p['header'] for p in present_all],
            'missing_headers': missing_all,
            'findings': findings,
            'raw_headers': raw_headers,
        }

    def run_cookie_check(self):
        self._log("\n[*] Cookie Security Flags")
        err = self._preflight('cookies')
        if err: return err

        findings, first_file, total = [], None, 0
        for svc in self.services:
            if first_file is None:
                first_file = self._write('cookies', svc['headers_raw'])
            cookies = svc['headers'].get('set-cookie', [])
            total += len(cookies)
            for cookie in cookies:
                name = cookie.split('=', 1)[0].strip()
                lower = cookie.lower()
                missing = []
                if 'secure' not in lower:   missing.append('Secure')
                if 'httponly' not in lower: missing.append('HttpOnly')
                if 'samesite' not in lower: missing.append('SameSite')
                for flag in missing:
                    findings.append(self._finding(
                        f"Cookie '{name}' missing {flag} flag",
                        severity='MEDIUM', evidence=cookie[:200],
                        url=svc['url'], check='cookies'))

        return {
            'output_file': first_file,
            'cookies_found': total,
            'findings': findings,
        }

    def run_http_methods_check(self):
        self._log("\n[*] Allowed HTTP Methods")
        err = self._preflight('http_methods', required_tool='curl')
        if err: return err

        findings, allowed, first_file = [], [], None
        for svc in self.services:
            args = ['curl', '-sI', '-X', 'OPTIONS', '--max-time', '10',
                    '-A', 'Mozilla/5.0 (compatible; WebAudit/6.0)', svc['url']]
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
                            severity='MEDIUM',
                            evidence=f"Allow: {match.group(1).strip()}",
                            url=svc['url'], check='http_methods'))

        return {
            'output_file': first_file,
            'allowed_methods': sorted(set(allowed)),
            'findings': findings,
        }

    def run_https_redirect_check(self):
        self._log("\n[*] HTTP to HTTPS Redirect")
        err = self._preflight('https_redirect')
        if err: return err

        http_svc = next((s for s in self.services if s['scheme'] == 'http'), None)
        https_svc = next((s for s in self.services if s['scheme'] == 'https'), None)
        if not https_svc:
            return {'error': 'No HTTPS service confirmed; cannot evaluate redirect'}
        if not http_svc:
            return {'error': 'No HTTP service confirmed; cannot evaluate redirect',
                    'status': 'not_applicable'}

        findings, status = [], 'unknown'
        if http_svc['status'] in (301, 302, 307, 308):
            loc = (http_svc['headers'].get('location') or [''])[0]
            if loc.lower().startswith('https://'):
                status = 'redirects_to_https'
            else:
                status = 'redirects_elsewhere'
                findings.append(self._finding(
                    "HTTP redirects but not to HTTPS", severity='MEDIUM',
                    evidence=f"Location: {loc}", url=http_svc['url'],
                    check='https_redirect'))
        else:
            status = 'no_redirect'
            findings.append(self._finding(
                "HTTP does not redirect to HTTPS", severity='MEDIUM',
                evidence=f"HTTP returned {http_svc['status']} with no redirect",
                url=http_svc['url'], check='https_redirect'))

        return {
            'output_file': self._write('redirect', http_svc['headers_raw']),
            'status': status,
            'findings': findings,
        }

    def run_info_disclosure_check(self):
        self._log("\n[*] Information Disclosure Headers")
        err = self._preflight('info_disclosure')
        if err: return err

        findings, first_file = [], None
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
                            severity='LOW', evidence=f"{header}: {value}",
                            url=svc['url'], check='info_disclosure'))
        return {'output_file': first_file, 'findings': findings}

    def run_cors_check(self):
        self._log("\n[*] CORS Configuration")
        err = self._preflight('cors')
        if err: return err

        findings, first_file = [], None
        evil = 'https://evil.example'
        for svc in self.services:
            args = ['curl', '-sS', '-k', '-i', '-H', f'Origin: {evil}',
                    '--max-time', '10',
                    '-A', 'Mozilla/5.0 (compatible; WebAudit/6.0)', svc['url']]
            result = self._run_command(args, timeout=15)
            if first_file is None:
                first_file = self._write('cors', result['stdout'])

            hdrs = self._parse_headers(result['stdout'])
            acao = (hdrs.get('access-control-allow-origin') or [''])[0]
            acac = (hdrs.get('access-control-allow-credentials') or [''])[0].lower()

            if acao == '*' and acac == 'true':
                findings.append(self._finding(
                    "CORS wildcard origin with credentials allowed",
                    severity='HIGH', evidence=f"ACAO: {acao}, ACAC: {acac}",
                    url=svc['url'], check='cors'))
            elif acao == evil:
                findings.append(self._finding(
                    "CORS reflects arbitrary Origin header",
                    severity='HIGH', evidence=f"ACAO reflected: {acao}",
                    url=svc['url'], check='cors'))
        return {'output_file': first_file, 'findings': findings}

    def run_sensitive_files_check(self):
        """Probe a fixed list of commonly-exposed paths.

        Classification by response:
          200 with body   -> HIGH (confirmed exposure)
          200 with 0 bytes-> INFO (executed PHP / empty handler)
          301/302/307/308 -> INFO (path exists, redirects)
          500             -> MEDIUM (server processed the path and failed)
        """
        self._log("\n[*] Sensitive File Exposure")
        err = self._preflight('sensitive_files', required_tool='curl')
        if err: return err

        findings = []
        output_file = os.path.join(self.output_dir, 'sensitive_files.txt')
        with open(output_file, 'w') as f:
            for svc in self.services:
                base = svc['url'].rstrip('/')
                for path in SENSITIVE_PATHS:
                    url = base + path
                    args = ['curl', '-s', '-o', os.devnull,
                            '-w', '%{http_code}|%{size_download}',
                            '--max-time', '8',
                            '-A', 'Mozilla/5.0 (compatible; WebAudit/6.0)',
                            url]
                    res = self._run_command(args, timeout=12)
                    raw = res['stdout'].strip()
                    code, size = (raw.split('|', 1) + ['0'])[:2] \
                        if '|' in raw else (raw, '0')
                    try:
                        size = int(size)
                    except ValueError:
                        size = 0
                    f.write(f"{code}\t{size}\t{url}\n")

                    if code == '200' and size > 0:
                        findings.append(self._finding(
                            f"Potentially exposed: {path} (HTTP 200, {size} bytes)",
                            severity='HIGH',
                            evidence=f"{url} returned {size} bytes",
                            url=url, check='sensitive_files'))
                    elif code == '200' and size == 0:
                        findings.append(self._finding(
                            f"Path exists but empty: {path} (HTTP 200, 0 bytes)",
                            severity='INFO',
                            evidence=f"{url} — likely an executed PHP file",
                            url=url, check='sensitive_files'))
                    elif code in ('301', '302', '307', '308'):
                        findings.append(self._finding(
                            f"Interesting path: {path} (HTTP {code})",
                            severity='INFO', evidence=f"{url} redirected",
                            url=url, check='sensitive_files'))
                    elif code == '500':
                        findings.append(self._finding(
                            f"Server error on path: {path} (HTTP 500)",
                            severity='MEDIUM',
                            evidence=f"{url} returned HTTP 500 — path was processed",
                            url=url, confidence='tentative',
                            check='sensitive_files'))

        return {'output_file': output_file, 'findings': findings}

    # ---------------------------------------------------- external tools

    def run_nmap_ssl(self):
        self._log("\n[*] Nmap - SSL/TLS Cipher Enumeration")
        err = self._preflight('ssl_nmap', required_tool='nmap')
        if err: return err

        https_services = [s for s in self.services if s['scheme'] == 'https']
        if not https_services:
            return {'error': 'No HTTPS service confirmed; skipping SSL enumeration'}

        findings, first_file, first_stdout = [], None, ''
        for svc in https_services:
            args = ['nmap', '-sV', '--script', 'ssl-enum-ciphers',
                    '-p', str(svc['port']), svc['host']]
            result = self._run_command(args, timeout=300)
            stdout = result['stdout']
            if first_file is None:
                first_file = self._write('nmap_ssl', stdout)
                first_stdout = stdout

            if re.search(r'SSLv2|SSLv3', stdout):
                findings.append(self._finding(
                    "Deprecated SSL versions detected", severity='HIGH',
                    evidence=f"nmap ssl-enum-ciphers for {svc['url']}",
                    url=svc['url'], check='ssl_nmap'))
            if 'WEAK' in stdout or 'broken' in stdout.lower():
                findings.append(self._finding(
                    "Weak ciphers detected", severity='HIGH',
                    evidence=f"nmap ssl-enum-ciphers for {svc['url']}",
                    url=svc['url'], check='ssl_nmap'))

        return {'output_file': first_file, 'summary': first_stdout[:800],
                'findings': findings}

    def run_testssl(self):
        self._log("\n[*] testssl.sh - Comprehensive SSL/TLS Scan")
        err = self._preflight('ssl_testssl', required_tool='testssl')
        if err: return err

        https_services = [s for s in self.services if s['scheme'] == 'https']
        if not https_services:
            return {'error': 'No HTTPS service confirmed; skipping testssl'}

        tool = self.available_tools['testssl_path']
        findings, first_file, first_stdout = [], None, ''
        for svc in https_services:
            args = [tool, '--quiet', '--color', '0', '--ip', 'one',
                    f"{svc['host']}:{svc['port']}"]
            result = self._run_command(args, timeout=self.timeout_ssl)
            content = result['stdout']
            if first_file is None:
                first_file = self._write('testssl', content)
                first_stdout = content

            if 'VULNERABLE' in content:
                findings.append(self._finding(
                    "TLS vulnerabilities reported by testssl",
                    severity='HIGH',
                    evidence=f"See testssl report for {svc['url']}",
                    url=svc['url'], check='ssl_testssl'))
            if 'Heartbleed' in content and 'not vulnerable' not in content.lower():
                findings.append(self._finding(
                    "Potential Heartbleed vulnerability", severity='HIGH',
                    evidence=f"testssl Heartbleed section for {svc['url']}",
                    url=svc['url'], confidence='tentative',
                    check='ssl_testssl'))

        return {'output_file': first_file, 'summary': first_stdout[:800],
                'findings': findings}

    def run_openssl_check(self):
        self._log("\n[*] OpenSSL - Certificate Inspection")
        err = self._preflight('ssl_certificate', required_tool='openssl')
        if err: return err

        https_services = [s for s in self.services if s['scheme'] == 'https']
        if not https_services:
            return {'error': 'No HTTPS service confirmed'}

        findings, cert_infos, first_file = [], {}, None
        for svc in https_services:
            s_client = self._run_command(
                ['openssl', 's_client', '-connect',
                 f"{svc['host']}:{svc['port']}",
                 '-servername', svc['host'], '-showcerts'],
                timeout=15, input_data='')
            x509 = self._run_command(
                ['openssl', 'x509', '-noout', '-text'],
                input_data=s_client['stdout'], timeout=15)
            text = x509['stdout']
            if first_file is None:
                first_file = self._write('ssl_cert', text)

            info = {}
            if text:
                issuer = re.search(r'Issuer:\s*(.+)', text)
                subject = re.search(r'Subject:\s*(.+)', text)
                not_before = re.search(r'Not Before:\s*(.+)', text)
                not_after = re.search(r'Not After\s*:\s*(.+)', text)

                if issuer:     info['issuer'] = issuer.group(1).strip()
                if subject:    info['subject'] = subject.group(1).strip()
                if not_before: info['valid_from'] = not_before.group(1).strip()
                if not_after:  info['valid_until'] = not_after.group(1).strip()

                if issuer and subject and \
                   issuer.group(1).strip() == subject.group(1).strip():
                    info['warning'] = 'Self-signed certificate detected'
                    findings.append(self._finding(
                        'Self-signed certificate detected', severity='MEDIUM',
                        evidence=f"issuer == subject: {subject.group(1).strip()}",
                        url=svc['url'], check='ssl_certificate'))

                if not_after:
                    try:
                        from email.utils import parsedate_to_datetime
                        exp = parsedate_to_datetime(not_after.group(1).strip())
                        days = (exp - datetime.now(timezone.utc)).days
                        info['days_to_expiry'] = days
                        if days < 0:
                            findings.append(self._finding(
                                f"TLS certificate expired {-days} days ago",
                                severity='HIGH',
                                evidence=f"Not After: {not_after.group(1).strip()}",
                                url=svc['url'], check='ssl_certificate'))
                        elif days < 30:
                            findings.append(self._finding(
                                f"TLS certificate expires in {days} days",
                                severity='MEDIUM',
                                evidence=f"Not After: {not_after.group(1).strip()}",
                                url=svc['url'], check='ssl_certificate'))
                    except Exception:
                        pass

            cert_infos[svc['url']] = info

        primary_info = cert_infos.get(self.primary_url) or \
            (next(iter(cert_infos.values())) if cert_infos else {})
        return {
            'output_file': first_file,
            'cert_info': primary_info,
            'cert_info_by_service': cert_infos,
            'findings': findings,
        }

    def run_whatweb(self):
        self._log("\n[*] WhatWeb - Technology Identification")
        err = self._preflight('whatweb', required_tool='whatweb')
        if err: return err

        first_file = None
        for svc in self.services:
            result = self._run_command(
                ['whatweb', '--color=never', '-a3', svc['url']], timeout=60)
            out = result['stdout'] or result['stderr']
            if first_file is None:
                first_file = self._write('whatweb', out)
        return {'output_file': first_file, 'findings': []}

    def run_nikto(self):
        """Run Nikto and keep every meaningful '+ ' finding line."""
        self._log("\n[*] Nikto - Web Server Scanner")
        err = self._preflight('nikto', required_tool='nikto')
        if err: return err

        # Metadata lines we don't want as findings.
        skip = re.compile(
            r'^(target\s+(ip|hostname|port)|start\s*time|end\s*time|'
            r'server\s*:|no cgi directories)', re.IGNORECASE)

        findings, first_file, first_stdout = [], None, ''
        for svc in self.services:
            output_file = os.path.join(
                self.output_dir, f"nikto_{_service_tag(svc['url'])}.txt")
            args = ['nikto', '-h', svc['url'], '-o', output_file,
                    '-Format', 'txt', '-nointeractive']
            result = self._run_command(args, timeout=self.timeout_nikto)
            if first_file is None:
                first_file = output_file
                first_stdout = result['stdout']

            if os.path.exists(output_file):
                with open(output_file, 'r', errors='replace') as f:
                    content = f.read()
                for line in content.splitlines():
                    stripped = line.strip()
                    if not stripped.startswith('+ '):
                        continue
                    text = stripped[2:].strip()
                    if skip.match(text.lower()):
                        continue
                    findings.append(self._finding(
                        f"Nikto: {text}",
                        evidence=f"nikto report for {svc['url']}",
                        url=svc['url'], check='nikto'))

        return {'output_file': first_file,
                'summary': first_stdout[:800] or 'See output file',
                'findings': findings}

    def _pick_wordlist(self):
        for p in WORDLIST_CANDIDATES:
            if os.path.exists(p):
                return p
        return None

    def _ffuf_rate_args(self):
        """Return ffuf flags for rate control, adapted to version.

        ffuf >= 1.3 supports -rate; older versions use -p (delay) + -t.
        """
        rc, out, err = self._run_command(['ffuf', '-h'], timeout=5)
        if '-rate' in (out + err).lower():
            return ['-rate', str(self.rate)]
        delay = 1.0 / max(self.rate, 1)
        return ['-p', f'{delay:.3f}', '-t', '10']

    def run_directory_scan(self):
        self._log("\n[*] Directory Discovery")
        err = self._preflight('directory_discovery')
        if err: return err

        results = {}

        # ffuf (preferred)
        if self.available_tools['ffuf']:
            wordlist = self.ffuf_wordlist
            if not wordlist or not os.path.exists(wordlist):
                wordlist = self._pick_wordlist()

            if wordlist:
                self._log(f"    ffuf wordlist: {wordlist}")
                rate_args = self._ffuf_rate_args()
                ffuf_findings, output_files = [], []
                for svc in self.services:
                    tag = _service_tag(svc['url'])
                    out_path = os.path.join(self.output_dir, f"ffuf_{tag}.json")
                    output_files.append(out_path)
                    args = ['ffuf', '-u', f"{svc['url'].rstrip('/')}/FUZZ",
                            '-w', wordlist, '-o', out_path, '-of', 'json',
                            '-mc', '200,204,301,302,307,401,403,500',
                            *rate_args, '-s']
                    result = self._run_command(args, timeout=self.timeout_dirscan)
                    if not result['success'] and result['stderr']:
                        self._log(f"    ffuf failed: {result['stderr'][:200]}")

                    if not os.path.exists(out_path):
                        self._log(f"    ffuf produced no output (exit "
                                  f"{result.get('returncode')})")
                        continue
                    try:
                        with open(out_path) as f:
                            data = json.load(f)
                        for hit in data.get('results', []):
                            status = hit.get('status')
                            url = hit.get('url', '')
                            length = hit.get('length')
                            if status in (200, 204, 301, 302, 307, 401, 403):
                                ffuf_findings.append(self._finding(
                                    f"Discovered: {url} (HTTP {status})",
                                    severity='INFO',
                                    evidence=f"{length} bytes",
                                    url=url, check='directory_discovery'))
                            elif status == 500:
                                ffuf_findings.append(self._finding(
                                    f"Server error on path: {url} (HTTP 500)",
                                    severity='MEDIUM',
                                    evidence=f"{length} bytes — path was processed",
                                    url=url, confidence='tentative',
                                    check='directory_discovery'))
                    except Exception as e:
                        self._log(f"    ffuf json parse error: {e}")

                results['ffuf'] = {
                    'output_file': output_files[0] if output_files else None,
                    'output_files': output_files,
                    'wordlist': wordlist,
                    'findings': ffuf_findings,
                }
            else:
                results['ffuf'] = {'error': 'No wordlist found'}

        # dirb (fallback)
        if self.available_tools['dirb']:
            self._log("    dirb")
            first_file = None
            for svc in self.services:
                out_path = os.path.join(
                    self.output_dir, f"dirb_{_service_tag(svc['url'])}.txt")
                if first_file is None:
                    first_file = out_path
                self._run_command(['dirb', svc['url'], '-o', out_path, '-S'],
                                  timeout=self.timeout_dirscan)
            results['dirb'] = {'output_file': first_file, 'findings': []}

        if not results:
            return {'error': 'Neither ffuf nor dirb is installed'}

        merged = []
        for r in results.values():
            if isinstance(r, dict):
                merged.extend(r.get('findings', []))
        results['findings'] = merged
        return results

    # ---------------------------------------------------------- reporting

    def generate_report(self):
        report = {
            'target': self.target_url,
            'timestamp': self.timestamp,
            'domain': self.domain,
            'run_directory': self.output_dir,
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
                'findings_by_severity': {k: [] for k in
                                         ('HIGH', 'MEDIUM', 'LOW', 'INFO')},
            },
        }

        # Aggregate findings into severity buckets.
        for check, result in self.results.items():
            if not isinstance(result, dict):
                continue
            for f in result.get('findings', []) or []:
                if isinstance(f, dict):
                    level = f.get('severity') or self._classify(f.get('title', ''))
                    entry = {
                        'title': f.get('title', ''),
                        'check': f.get('check') or check,
                        'url': f.get('url'),
                        'evidence': f.get('evidence'),
                        'confidence': f.get('confidence', 'confirmed'),
                    }
                else:
                    level = self._classify(str(f))
                    entry = {'title': str(f), 'check': check, 'url': None,
                             'evidence': None, 'confidence': 'confirmed'}
                report['summary']['findings_by_severity'].setdefault(
                    level, []).append(entry)

            cert = result.get('cert_info', {})
            if isinstance(cert, dict) and 'warning' in cert:
                report['summary']['findings_by_severity'].setdefault(
                    self._classify(cert['warning']), []).append({
                        'title': cert['warning'], 'check': 'ssl_certificate',
                        'url': self.primary_url, 'evidence': None,
                        'confidence': 'confirmed'})

        json_file = os.path.join(self.output_dir, 'security_audit_report.json')
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        txt_file = os.path.join(self.output_dir, 'security_audit_summary.txt')
        self._write_text_report(report, txt_file)

        html_file = os.path.join(self.output_dir, 'audit_report.html')
        self._write_html_report(report, html_file)

        return {'json_report': json_file, 'summary_report': txt_file,
                'html_report': html_file, 'report_data': report}

    def _write_text_report(self, report, path):
        sev = report['summary']['findings_by_severity']
        with open(path, 'w') as f:
            f.write("=" * 70 + "\n")
            f.write("WEB SECURITY AUDIT REPORT\n")
            f.write(f"Target: {report['target']}\n")
            f.write(f"Date:   {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Run:    {report.get('run_directory', '')}\n")
            f.write("=" * 70 + "\n\n")

            f.write("EXECUTIVE SUMMARY\n" + "-" * 70 + "\n")
            f.write(f"Checks performed      : {report['summary']['total_checks']}\n")
            f.write(f"Web service reachable : "
                    f"{'yes' if report['summary']['web_service_reachable'] else 'no'}\n")
            for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
                f.write(f"{level:<22}: {len(sev[level])}\n")
            f.write("\n")

            for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
                if not sev[level]:
                    continue
                f.write(f"{level} FINDINGS\n" + "-" * 70 + "\n")
                for item in sev[level]:
                    conf = item.get('confidence', '')
                    url = item.get('url') or ''
                    line = f"  [{conf}] {item.get('title', str(item))}"
                    if url:
                        line += f"  ({url})"
                    f.write(line + "\n")
                f.write("\n")

            f.write("\nDETAILED RESULTS\n" + "-" * 70 + "\n")
            for check, result in self.results.items():
                f.write(f"\n[{check.upper()}]\n")
                if not isinstance(result, dict):
                    f.write(f"  {result}\n")
                    continue
                if 'error' in result:
                    f.write(f"  Error: {result['error']}\n")
                if result.get('output_file'):
                    f.write(f"  Output: {result['output_file']}\n")
                if result.get('summary'):
                    s = str(result['summary']).replace('\n', ' ')
                    f.write(f"  Summary: {s[:250]}...\n")

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
            "<h1>Security Audit Report</h1>",
            f"<p class='meta'><b>Target:</b> {e(report['target'])}<br>",
            f"<b>Web service reachable:</b> "
            f"{'yes' if report['summary']['web_service_reachable'] else 'no'}<br>",
            f"<b>Run folder:</b> <code>{e(report.get('run_directory', ''))}</code><br>",
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
                parts.append("<li>" + e(item.get('title', str(item))))
                conf = item.get('confidence', '')
                if conf:
                    parts.append(f"<span class='conf'>[{e(conf)}]</span>")
                if item.get('evidence'):
                    parts.append(f"<span class='ev'>{e(str(item['evidence']))}</span>")
                if item.get('url'):
                    parts.append(f"<span class='ev'><code>{e(item['url'])}</code></span>")
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
            if result.get('error'):
                parts.append(f"<i>Error:</i> {e(str(result['error']))}<br>")
            if result.get('output_file'):
                parts.append(f"<i>Output:</i> <code>{e(str(result['output_file']))}</code><br>")
            if result.get('summary'):
                s = str(result['summary'])[:300].replace('\n', ' ')
                parts.append(f"<i>Summary:</i> {e(s)}...")
            parts.append("</div>")

        parts.append("</body></html>")

        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(parts))

    # ------------------------------------------------------------ driver

    ALL_CHECKS = [
        ('body_analysis',       'run_body_analysis_check'),
        ('page_analysis',       'run_page_analysis_check'),
        ('whatweb',             'run_whatweb'),
        ('ssl_nmap',            'run_nmap_ssl'),
        ('ssl_testssl',         'run_testssl'),
        ('ssl_certificate',     'run_openssl_check'),
        ('security_headers',    'run_security_headers_check'),
        ('cookies',             'run_cookie_check'),
        ('http_methods',        'run_http_methods_check'),
        ('https_redirect',      'run_https_redirect_check'),
        ('info_disclosure',     'run_info_disclosure_check'),
        ('cors',                'run_cors_check'),
        ('sensitive_files',     'run_sensitive_files_check'),
        ('nikto',               'run_nikto'),
        ('directory_discovery', 'run_directory_scan'),
    ]

    def _selected_checks(self):
        if self.only_checks:
            return [(n, getattr(self, m)) for n, m in self.ALL_CHECKS
                    if n in self.only_checks]
        return [(n, getattr(self, m)) for n, m in self.ALL_CHECKS
                if n not in self.skip_checks]

    def run_full_audit(self):
        self._log("=" * 70, always=True)
        self._log(f"STARTING SECURITY AUDIT FOR: {self.target_url}", always=True)
        self._log(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", always=True)
        self._log(f"Output folder: {self.output_dir}", always=True)
        self._log("=" * 70, always=True)

        # Service discovery always runs first and gates the rest.
        try:
            self.results['service_discovery'] = self.run_service_discovery()
        except Exception as e:
            self.results['service_discovery'] = {'error': f'Unhandled: {e}'}
            self._log(f"[-] Error in service_discovery: {e}", always=True)

        checks = self._selected_checks()
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
        self._log(f"Run folder  : {self.output_dir}", always=True)
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
        epilog='Example: python3 audit_deepseek.py https://example.com -o results')
    parser.add_argument('target', help='Target URL or host')
    parser.add_argument('-o', '--output', default='audit_results',
                        help='Base output dir; a per-run subfolder is created '
                             'inside it (default: audit_results)')
    parser.add_argument('-c', '--config', default=None,
                        help='Path to JSON config file')
    parser.add_argument('--skip', nargs='*', default=[],
                        help='Names of checks to skip')
    parser.add_argument('--only', nargs='*', default=[],
                        help='Run only these checks')
    parser.add_argument('--ports', default=None,
                        help='Extra ports to probe during discovery '
                             '(e.g. 80,443,8080)')
    parser.add_argument('--flat', action='store_true',
                        help='Disable per-run subfolders; write directly into '
                             'the output directory')
    parser.add_argument('-q', '--quiet', action='store_true',
                        help='Only print the final summary')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Print each external command being run')
    parser.add_argument('--rate', type=int, default=50,
                        help='ffuf request rate (default 50)')
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

    ports = [p.strip() for p in args.ports.split(',')] if args.ports else None

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
        flat_output=args.flat,
    )

    try:
        auditor.run_full_audit()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Partial results saved in", auditor.output_dir)
        sys.exit(130)


if __name__ == '__main__':
    main()