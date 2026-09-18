#!/usr/bin/env python3
"""
Web Security Audit Automation Script
For educational purposes only.
Only use on systems you own or have explicit written permission to test.

Usage:
    python3 audit_deepseek.py https://example.com
    python3 audit_deepseek.py https://example.com -o results --skip nikto directory_discovery
    python3 audit_deepseek.py https://example.com --only ssl_testssl security_headers
    python3 audit_deepseek.py https://example.com --config audit_config.json
"""

import subprocess
import sys
import os
import argparse
import json
import re
import shutil
import signal
from datetime import datetime
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Severity classification rules. Checked in order; first match wins.
# Pattern is case-insensitive substring match against the finding text.
SEVERITY_RULES = [
    ('Heartbleed', 'HIGH'),
    ('VULNERABLE', 'HIGH'),
    ('Dangerous HTTP method', 'HIGH'),
    ('Potentially exposed', 'HIGH'),
    ('Deprecated SSL', 'HIGH'),
    ('Weak ciphers', 'HIGH'),
    ('does not redirect to HTTPS', 'HIGH'),
    ('missing Secure flag', 'MEDIUM'),
    ('missing HttpOnly flag', 'MEDIUM'),
    ('missing SameSite', 'MEDIUM'),
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

# Files/paths we test for accidental exposure.
SENSITIVE_PATHS = [
    '/.env', '/.git/config', '/.git/HEAD', '/.svn/entries',
    '/wp-config.php.bak', '/config.php.bak', '/backup.zip',
    '/.htaccess', '/phpinfo.php', '/server-status',
    '/.DS_Store', '/web.config', '/composer.json',
    '/package.json',
]

# Candidate wordlist locations for directory brute-forcing.
WORDLIST_CANDIDATES = [
    "/snap/seclists/current/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
    "/usr/share/wordlists/dirb/common.txt",
]


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

class WebSecurityAuditor:

    def __init__(self, target_url, output_dir="audit_results",
                 config=None, skip_checks=None, only_checks=None,
                 quiet=False, verbose=False, rate=50):
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

        # Merge config over defaults.
        cfg = config or {}
        self.timeout_default  = cfg.get('timeout', 300)
        self.whatweb_aggr     = cfg.get('whatweb_aggression', 3)
        self.ffuf_wordlist    = cfg.get('ffuf_wordlist')
        self.timeout_ssltest  = cfg.get('timeout_ssl', 600)
        self.timeout_nikto    = cfg.get('timeout_nikto', 600)
        self.timeout_dirscan  = cfg.get('timeout_dirscan', 600)

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
        # testssl.sh has two possible names depending on install
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
        """Return severity level for a finding string."""
        low = text.lower()
        for pattern, level in SEVERITY_RULES:
            if pattern.lower() in low:
                return level
        return 'INFO'

    # ----------------------------------------------------------------- checks

    def run_whatweb(self):
        """Identify web technologies in use."""
        self._log("\n[*] WhatWeb - Technology Identification")
        if not self.available_tools['whatweb']:
            return {'error': 'whatweb not installed'}

        args = ['whatweb', '-v', f'-a{self.whatweb_aggr}', self.target_url]
        result = self._run_command(args)
        output_file = self._write('whatweb', result['stdout'])

        return {
            'output_file': output_file,
            'summary': (result['stdout'][:800] or result['stderr']),
            'findings': [],
        }

    def run_nmap_ssl(self):
        """Enumerate supported SSL/TLS cipher suites and versions."""
        self._log("\n[*] Nmap - SSL/TLS Cipher Enumeration")
        if not self.available_tools['nmap']:
            return {'error': 'nmap not installed'}
        if self.parsed_url.scheme != 'https':
            return {'error': 'Target is not HTTPS; skipping SSL enumeration'}

        port = self.parsed_url.port or 443
        args = ['nmap', '-sV', '--script', 'ssl-enum-ciphers',
                '-p', str(port), self.hostname]
        result = self._run_command(args)
        output_file = self._write('nmap_ssl', result['stdout'])

        findings = []
        stdout = result['stdout']
        if re.search(r'SSLv2|SSLv3', stdout):
            findings.append("Deprecated SSL versions detected")
        if 'WEAK' in stdout or 'broken' in stdout.lower():
            findings.append("Weak ciphers detected")

        return {
            'output_file': output_file,
            'findings': findings,
            'summary': (stdout[:800] or result['stderr']),
        }

    def run_testssl(self):
        """Run comprehensive SSL/TLS vulnerability tests."""
        self._log("\n[*] testssl.sh - Comprehensive SSL/TLS Scan")
        if not self.available_tools['testssl']:
            return {'error': 'testssl.sh not installed'}
        if self.parsed_url.scheme != 'https':
            return {'error': 'Target is not HTTPS; skipping testssl'}

        tool = self.available_tools['testssl_path']
        port = self.parsed_url.port or 443
        args = [tool, '--quiet', '--color', '0',
                '--ip', 'one', f'{self.hostname}:{port}']
        result = self._run_command(args, timeout=self.timeout_ssltest)
        output_file = self._write('testssl', result['stdout'])

        findings = []
        content = result['stdout']
        if 'VULNERABLE' in content:
            findings.append("Vulnerabilities detected - see full testssl report")
        if 'Heartbleed' in content and 'not vulnerable' not in content.lower():
            findings.append("Potential Heartbleed vulnerability")

        return {'output_file': output_file, 'findings': findings}

    def run_openssl_check(self):
        """Inspect the SSL certificate chain and details."""
        self._log("\n[*] OpenSSL - Certificate Inspection")
        if not self.available_tools['openssl']:
            return {'error': 'openssl not installed'}
        if self.parsed_url.scheme != 'https':
            return {'error': 'Target is not HTTPS'}

        port = self.parsed_url.port or 443

        # Pipe s_client output into x509 without shell.
        connect_args = ['openssl', 's_client', '-connect',
                        f'{self.hostname}:{port}', '-servername', self.hostname,
                        '-showcerts']
        s_client = self._run_command(connect_args, input_data='')
        x509 = self._run_command(['openssl', 'x509', '-noout', '-text'],
                                 input_data=s_client['stdout'])
        output_file = self._write('ssl_cert', x509['stdout'])

        cert_info = {}
        text = x509['stdout']
        if text:
            issuer     = re.search(r'Issuer:\s*(.+)', text)
            subject    = re.search(r'Subject:\s*(.+)', text)
            not_before = re.search(r'Not Before:\s*(.+)', text)
            not_after  = re.search(r'Not After\s*:\s*(.+)', text)

            if issuer:     cert_info['issuer']      = issuer.group(1).strip()
            if subject:    cert_info['subject']     = subject.group(1).strip()
            if not_before: cert_info['valid_from']  = not_before.group(1).strip()
            if not_after:  cert_info['valid_until'] = not_after.group(1).strip()

            if issuer and subject and issuer.group(1).strip() == subject.group(1).strip():
                cert_info['warning'] = 'Self-signed certificate detected'

        findings = []
        if 'warning' in cert_info:
            findings.append(cert_info['warning'])

        return {
            'output_file': output_file,
            'cert_info': cert_info,
            'findings': findings,
        }

    def run_security_headers_check(self):
        """Check for presence of common HTTP security headers."""
        self._log("\n[*] HTTP Security Headers")
        if not self.available_tools['curl']:
            return {'error': 'curl not installed'}

        args = ['curl', '-sIL', self.target_url]
        result = self._run_command(args)
        output_file = self._write('headers', result['stdout'])

        present, missing = [], []
        headers_lower = result['stdout'].lower()
        for header, message in SECURITY_HEADERS.items():
            if f"{header.lower()}:" in headers_lower:
                present.append(header)
            else:
                missing.append({'header': header, 'issue': message})

        findings = [m['issue'] for m in missing]
        return {
            'output_file': output_file,
            'present_headers': present,
            'missing_headers': missing,
            'findings': findings,
            'raw_headers': result['stdout'],
        }

    def run_cookie_check(self):
        """Check Set-Cookie headers for missing security attributes."""
        self._log("\n[*] Cookie Security Flags")
        if not self.available_tools['curl']:
            return {'error': 'curl not installed'}

        args = ['curl', '-sIL', self.target_url]
        result = self._run_command(args)
        output_file = self._write('cookies', result['stdout'])

        findings = []
        cookies = re.findall(r'^Set-Cookie:\s*(.+)$',
                             result['stdout'],
                             re.IGNORECASE | re.MULTILINE)
        for cookie in cookies:
            name = cookie.split('=', 1)[0].strip()
            lower = cookie.lower()
            if 'secure' not in lower:
                findings.append(f"Cookie '{name}' missing Secure flag")
            if 'httponly' not in lower:
                findings.append(f"Cookie '{name}' missing HttpOnly flag")
            if 'samesite' not in lower:
                findings.append(f"Cookie '{name}' missing SameSite attribute")

        return {
            'output_file': output_file,
            'findings': findings,
            'cookies_found': len(cookies),
        }

    def run_http_methods_check(self):
        """Check which HTTP methods the server advertises via OPTIONS."""
        self._log("\n[*] Allowed HTTP Methods")
        if not self.available_tools['curl']:
            return {'error': 'curl not installed'}

        args = ['curl', '-sI', '-X', 'OPTIONS', self.target_url]
        result = self._run_command(args)
        output_file = self._write('methods', result['stdout'])

        findings, allowed = [], []
        match = re.search(r'^Allow:\s*(.+)$', result['stdout'],
                          re.IGNORECASE | re.MULTILINE)
        if match:
            allowed = [m.strip().upper() for m in match.group(1).split(',')]
            for dangerous in ('TRACE', 'PUT', 'DELETE', 'CONNECT'):
                if dangerous in allowed:
                    findings.append(f"Dangerous HTTP method enabled: {dangerous}")

        return {
            'output_file': output_file,
            'findings': findings,
            'allowed_methods': allowed,
        }

    def run_https_redirect_check(self):
        """Verify HTTP traffic redirects to HTTPS."""
        self._log("\n[*] HTTP to HTTPS Redirect")
        if not self.available_tools['curl']:
            return {'error': 'curl not installed'}
        if self.parsed_url.scheme != 'https':
            return {'error': 'Target is not HTTPS; cannot test redirect'}

        http_url = self.target_url.replace('https://', 'http://', 1)
        args = ['curl', '-sI', '--max-time', '15', http_url]
        result = self._run_command(args)
        output_file = self._write('redirect', result['stdout'])

        findings = []
        status = 'unknown'
        head = result['stdout'].lower()
        if any(code in result['stdout'] for code in ('301', '302', '307', '308')):
            if 'location: https://' in head or 'location: https' in head:
                status = 'redirects_to_https'
            else:
                status = 'redirects_elsewhere'
                findings.append("HTTP redirects but not to HTTPS")
        else:
            status = 'no_redirect'
            findings.append("HTTP does not redirect to HTTPS")

        return {'output_file': output_file, 'findings': findings, 'status': status}

    def run_info_disclosure_check(self):
        """Flag version disclosure in server headers."""
        self._log("\n[*] Information Disclosure Headers")
        if not self.available_tools['curl']:
            return {'error': 'curl not installed'}

        args = ['curl', '-sIL', self.target_url]
        result = self._run_command(args)
        output_file = self._write('disclosure', result['stdout'])

        findings = []
        for header in ('Server', 'X-Powered-By', 'X-AspNet-Version',
                       'X-Generator', 'X-Drupal-Cache'):
            m = re.search(rf'^{header}:\s*(.+)$', result['stdout'],
                          re.IGNORECASE | re.MULTILINE)
            if m:
                value = m.group(1).strip()
                if re.search(r'\d', value):
                    findings.append(f"{header} discloses version: {value}")

        return {'output_file': output_file, 'findings': findings}

    def run_sensitive_files_check(self):
        """Probe a small list of commonly exposed sensitive paths."""
        self._log("\n[*] Sensitive File Exposure")
        if not self.available_tools['curl']:
            return {'error': 'curl not installed'}

        findings = []
        output_file = os.path.join(self.output_dir,
                                   f"sensitive_files_{self.timestamp}.txt")
        with open(output_file, 'w') as f:
            for path in SENSITIVE_PATHS:
                url = f"{self.target_url}{path}"
                args = ['curl', '-s', '-o', os.devnull,
                        '-w', '%{http_code}', '--max-time', '10', url]
                res = self._run_command(args, timeout=15)
                code = res['stdout'].strip()
                f.write(f"{code}\t{url}\n")
                if code in ('200', '301', '302', '307'):
                    findings.append(f"Potentially exposed: {path} (HTTP {code})")

        return {'output_file': output_file, 'findings': findings}

    def run_nikto(self):
        """Run Nikto web server vulnerability scanner."""
        self._log("\n[*] Nikto - Web Server Scanner")
        if not self.available_tools['nikto']:
            return {'error': 'nikto not installed'}

        output_file = os.path.join(self.output_dir,
                                   f"nikto_{self.timestamp}.txt")
        args = ['nikto', '-h', self.target_url, '-o', output_file, '-Format', 'txt']
        result = self._run_command(args, timeout=self.timeout_nikto)

        findings = []
        if os.path.exists(output_file):
            with open(output_file, 'r', errors='replace') as f:
                content = f.read()
            # Nikto prefixes actual findings with "+ "
            nikto_findings = [ln for ln in content.splitlines()
                              if ln.strip().startswith('+ ')]
            for line in nikto_findings:
                low = line.lower()
                if 'osvdb' in low:
                    findings.append(f"Nikto: {line.strip()[2:]}")
                if 'server leaks' in low or 'server may leak' in low:
                    findings.append(f"Nikto: {line.strip()[2:]}")

        return {
            'output_file': output_file,
            'findings': findings,
            'summary': (result['stdout'][:800] or 'See output file'),
        }

    def run_directory_scan(self):
        """Discover hidden directories/files using ffuf and/or dirb."""
        self._log("\n[*] Directory Discovery")
        results = {}

        # ---- ffuf (preferred) ----
        if self.available_tools['ffuf']:
            self._log("    using ffuf")
            wordlist = self.ffuf_wordlist
            if not wordlist or not os.path.exists(wordlist):
                wordlist = next((p for p in WORDLIST_CANDIDATES
                                 if os.path.exists(p)), None)

            if wordlist:
                output_file = os.path.join(
                    self.output_dir, f"ffuf_{self.timestamp}.json")
                args = ['ffuf',
                        '-u', f'{self.target_url}/FUZZ',
                        '-w', wordlist,
                        '-o', output_file,
                        '-of', 'json',
                        '-rate', str(self.rate),
                        '-s']
                result = self._run_command(args, timeout=self.timeout_dirscan)

                ffuf_findings = []
                if os.path.exists(output_file):
                    try:
                        with open(output_file) as f:
                            data = json.load(f)
                        for hit in data.get('results', []):
                            status = hit.get('status')
                            url    = hit.get('url', '')
                            if status in (200, 301, 302, 401, 403):
                                ffuf_findings.append(
                                    f"Discovered: {url} (HTTP {status})")
                    except Exception:
                        pass

                results['ffuf'] = {
                    'output_file': output_file,
                    'success': result['success'],
                    'findings': ffuf_findings,
                }
            else:
                results['ffuf'] = {'error': 'No wordlist found'}

        # ---- dirb (fallback / additional) ----
        if self.available_tools['dirb']:
            self._log("    using dirb")
            output_file = os.path.join(
                self.output_dir, f"dirb_{self.timestamp}.txt")
            args = ['dirb', self.target_url, '-o', output_file, '-S']
            result = self._run_command(args, timeout=self.timeout_dirscan)
            results['dirb'] = {
                'output_file': output_file,
                'success': result['success'],
                'findings': [],
            }

        if not results:
            return {'error': 'Neither ffuf nor dirb is installed'}

        # Merge findings for the summary
        merged = []
        for tool, r in results.items():
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
            'results': self.results,
            'summary': {
                'total_checks': len(self.results),
                'findings_by_severity': {
                    'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []
                },
            },
        }

        # Aggregate findings and classify.
        for check, result in self.results.items():
            if not isinstance(result, dict):
                continue
            for f in result.get('findings', []) or []:
                level = self._classify(f)
                report['summary']['findings_by_severity'][level].append(f)
            # Certificate warning
            cert = result.get('cert_info', {})
            if isinstance(cert, dict) and 'warning' in cert:
                level = self._classify(cert['warning'])
                report['summary']['findings_by_severity'][level].append(
                    cert['warning'])

        # --- JSON ---
        json_file = os.path.join(self.output_dir,
                                 f"security_audit_report_{self.timestamp}.json")
        with open(json_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        # --- Human-readable text ---
        txt_file = os.path.join(self.output_dir,
                                f"security_audit_summary_{self.timestamp}.txt")
        self._write_text_report(report, txt_file)

        # --- HTML ---
        html_file = os.path.join(self.output_dir,
                                 f"audit_report_{self.timestamp}.html")
        self._write_html_report(report, html_file)

        return {
            'json_report': json_file,
            'summary_report': txt_file,
            'html_report': html_file,
            'report_data': report,
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
            f.write(f"Checks performed : {report['summary']['total_checks']}\n")
            for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
                f.write(f"{level:<17}: {len(sev[level])}\n")
            f.write("\n")

            for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
                if not sev[level]:
                    continue
                f.write(f"{level} FINDINGS\n")
                f.write("-" * 70 + "\n")
                for item in sev[level]:
                    f.write(f"  * {item}\n")
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
                if 'output_file' in result:
                    f.write(f"  Output file: {result['output_file']}\n")
                if 'summary' in result:
                    summary = result['summary'].replace('\n', ' ')
                    f.write(f"  Summary: {summary[:250]}...\n")

    def _write_html_report(self, report, path):
        sev = report['summary']['findings_by_severity']
        colors = {'HIGH': '#d32f2f', 'MEDIUM': '#f57c00',
                  'LOW': '#fbc02d', 'INFO': '#0288d1'}

        parts = [
            "<!DOCTYPE html>",
            "<html><head><meta charset='utf-8'>",
            f"<title>Audit Report - {report['target']}</title>",
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
            "</style></head><body>",
            f"<h1>Security Audit Report</h1>",
            f"<p class='meta'><b>Target:</b> {report['target']}<br>",
            f"<b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>",
        ]

        # Summary table
        parts.append("<h2>Executive Summary</h2>")
        parts.append("<table style='border-collapse:collapse'>")
        for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
            parts.append(
                f"<tr><td><span class='badge' style='background:{colors[level]}'>"
                f"{level}</span></td><td>{len(sev[level])} finding(s)</td></tr>")
        parts.append("</table>")

        # Findings by severity
        for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
            parts.append(f"<h2>{level} Findings</h2>")
            if not sev[level]:
                parts.append("<p class='none'>None</p>")
                continue
            parts.append("<ul>")
            for f in sev[level]:
                parts.append(f"<li>{f}</li>")
            parts.append("</ul>")

        # Detailed per-check
        parts.append("<h2>Detailed Results</h2>")
        for check, result in self.results.items():
            parts.append(f"<div class='check'><b>{check}</b><br>")
            if not isinstance(result, dict):
                parts.append(f"{result}</div>")
                continue
            if 'error' in result:
                parts.append(f"<i>Error:</i> {result['error']}<br>")
            if 'output_file' in result:
                parts.append(f"<i>Output:</i> <code>{result['output_file']}</code><br>")
            if 'summary' in result:
                s = result['summary'][:300].replace('\n', ' ')
                parts.append(f"<i>Summary:</i> {s}...")
            parts.append("</div>")

        parts.append("</body></html>")

        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(parts))

    # ------------------------------------------------------------------ driver

    def run_full_audit(self):
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
            ('sensitive_files',     self.run_sensitive_files_check),
            ('nikto',               self.run_nikto),
            ('directory_discovery', self.run_directory_scan),
        ]

        # Apply --only / --skip filters
        if self.only_checks:
            checks = [(n, fn) for n, fn in all_checks if n in self.only_checks]
        else:
            checks = [(n, fn) for n, fn in all_checks
                      if n not in self.skip_checks]

        self._log("=" * 70, always=True)
        self._log(f"STARTING SECURITY AUDIT FOR: {self.target_url}", always=True)
        self._log(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", always=True)
        self._log(f"Checks to run: {', '.join(n for n, _ in checks)}", always=True)
        self._log("=" * 70, always=True)

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
                        help='Target URL (e.g., https://example.com)')
    parser.add_argument('-o', '--output', default='audit_results',
                        help='Output directory (default: audit_results)')
    parser.add_argument('-c', '--config', default=None,
                        help='Path to JSON config file')
    parser.add_argument('--skip', nargs='*', default=[],
                        help='Names of checks to skip')
    parser.add_argument('--only', nargs='*', default=[],
                        help='Run only these checks')
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

    # Legal warning
    print("\n" + "!" * 70)
    print("WARNING: Only use this tool on systems you own or have")
    print("explicit written permission to test. Unauthorized scanning")
    print("is illegal and unethical.")
    print("!" * 70 + "\n")

    auditor = WebSecurityAuditor(
        target_url=args.target,
        output_dir=args.output,
        config=config,
        skip_checks=args.skip,
        only_checks=args.only,
        quiet=args.quiet,
        verbose=args.verbose,
        rate=args.rate,
    )

    try:
        auditor.run_full_audit()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Partial results saved in",
              args.output)
        sys.exit(130)


if __name__ == '__main__':
    main()