#!/usr/bin/env python3
"""
Web Security Audit Automation Script
For educational purposes only. Only use on systems you own or have explicit permission to test.
"""

import subprocess
import sys
import os
import argparse
import json
import re
from datetime import datetime
from urllib.parse import urlparse
import shutil

class WebSecurityAuditor:
    def __init__(self, target_url, output_dir="audit_results"):
        self.target_url = target_url.rstrip('/')
        self.parsed_url = urlparse(self.target_url)
        self.domain = self.parsed_url.netloc
        self.output_dir = output_dir
        self.results = {}
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create output directory
        os.makedirs(self.output_dir, exist_ok=True)
        
        # Check which tools are available
        self.available_tools = self._check_tools()
        
    def _check_tools(self):
        """Check which required tools are installed"""
        tools = {
            'whatweb': 'whatweb',
            'nmap': 'nmap',
            'nikto': 'nikto',
            'dirb': 'dirb',
            'ffuf': 'ffuf',
            'openssl': 'openssl',
            'curl': 'curl',
            'testssl': 'testssl.sh'
        }
        
        available = {}
        for tool_name, command in tools.items():
            if shutil.which(command):
                available[tool_name] = True
                print(f"[+] Found: {tool_name}")
            else:
                available[tool_name] = False
                print(f"[-] Missing: {tool_name} (install to enable this check)")
        
        return available
    
    def _run_command(self, command, timeout=300):
        """Execute a shell command and return output"""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'returncode': result.returncode
            }
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'stdout': '',
                'stderr': f'Command timed out after {timeout} seconds',
                'returncode': -1
            }
        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'returncode': -1
            }
    
    def run_whatweb(self):
        """Identify web technologies"""
        print("\n[*] Running WhatWeb - Technology Identification...")
        
        if not self.available_tools.get('whatweb'):
            return {'error': 'whatweb not installed'}
        
        command = f"whatweb -v -a 3 {self.target_url}"
        result = self._run_command(command)
        
        output_file = os.path.join(self.output_dir, f"whatweb_{self.timestamp}.txt")
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        
        return {
            'output_file': output_file,
            'summary': result['stdout'][:500] if result['stdout'] else result['stderr']
        }
    
    def run_nmap_ssl(self):
        """Check SSL/TLS configuration with nmap"""
        print("\n[*] Running Nmap SSL/TLS Enumeration...")
        
        if not self.available_tools.get('nmap'):
            return {'error': 'nmap not installed'}
        
        port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)
        command = f"nmap -sV --script ssl-enum-ciphers -p {port} {self.domain}"
        result = self._run_command(command)
        
        output_file = os.path.join(self.output_dir, f"nmap_ssl_{self.timestamp}.txt")
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        
        # Parse for weak ciphers
        weak_findings = []
        if 'SSLv2' in result['stdout'] or 'SSLv3' in result['stdout']:
            weak_findings.append("Deprecated SSL versions detected")
        if 'WEAK' in result['stdout'] or 'broken' in result['stdout'].lower():
            weak_findings.append("Weak ciphers detected")
        
        return {
            'output_file': output_file,
            'findings': weak_findings,
            'summary': result['stdout'][:500] if result['stdout'] else result['stderr']
        }
    
    def run_testssl(self):
        """Run comprehensive SSL/TLS test"""
        print("\n[*] Running testssl.sh - Comprehensive SSL/TLS Test...")
        
        if not self.available_tools.get('testssl'):
            return {'error': 'testssl.sh not installed'}
        
        output_file = os.path.join(self.output_dir, f"testssl_{self.timestamp}.txt")
        command = f"testssl.sh --quiet --color 0 {self.domain} > {output_file}"
        result = self._run_command(command, timeout=600)
        
        # Check for critical vulnerabilities
        critical_findings = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                content = f.read()
                if 'VULNERABLE' in content:
                    critical_findings.append("Vulnerabilities detected - check full report")
                if 'Heartbleed' in content and 'not vulnerable' not in content.lower():
                    critical_findings.append("Potential Heartbleed vulnerability")
        
        return {
            'output_file': output_file,
            'findings': critical_findings
        }
    
    def run_openssl_check(self):
        """Check SSL certificate details"""
        print("\n[*] Running OpenSSL Certificate Check...")
        
        if not self.available_tools.get('openssl'):
            return {'error': 'openssl not installed'}
        
        if self.parsed_url.scheme != 'https':
            return {'error': 'Target is not HTTPS'}
        
        command = f"echo | openssl s_client -connect {self.domain}:443 -servername {self.domain} -showcerts 2>/dev/null | openssl x509 -noout -text"
        result = self._run_command(command)
        
        output_file = os.path.join(self.output_dir, f"ssl_cert_{self.timestamp}.txt")
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        
        # Parse certificate info
        cert_info = {}
        if result['stdout']:
            # Extract issuer
            issuer_match = re.search(r'Issuer: (.+)', result['stdout'])
            if issuer_match:
                cert_info['issuer'] = issuer_match.group(1).strip()
            
            # Extract validity
            not_before = re.search(r'Not Before: (.+)', result['stdout'])
            not_after = re.search(r'Not After : (.+)', result['stdout'])
            if not_before:
                cert_info['valid_from'] = not_before.group(1).strip()
            if not_after:
                cert_info['valid_until'] = not_after.group(1).strip()
            
            # Check for self-signed
            if 'Issuer' in result['stdout'] and 'Subject' in result['stdout']:
                issuer = re.search(r'Issuer: (.+)', result['stdout'])
                subject = re.search(r'Subject: (.+)', result['stdout'])
                if issuer and subject and issuer.group(1) == subject.group(1):
                    cert_info['warning'] = 'Self-signed certificate detected'
        
        return {
            'output_file': output_file,
            'cert_info': cert_info
        }
    
    def run_security_headers_check(self):
        """Check HTTP security headers"""
        print("\n[*] Checking HTTP Security Headers...")
        
        if not self.available_tools.get('curl'):
            return {'error': 'curl not installed'}
        
        command = f"curl -sI -L {self.target_url}"
        result = self._run_command(command)
        
        output_file = os.path.join(self.output_dir, f"headers_{self.timestamp}.txt")
        with open(output_file, 'w') as f:
            f.write(result['stdout'])
        
        # Check for important security headers
        headers_to_check = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'Content-Security-Policy': 'CSP not implemented',
            'X-Frame-Options': 'Clickjacking protection missing',
            'X-Content-Type-Options': 'MIME sniffing protection missing',
            'Referrer-Policy': 'Referrer policy not set',
            'Permissions-Policy': 'Permissions policy not set'
        }
        
        missing_headers = []
        present_headers = []
        
        for header, message in headers_to_check.items():
            if header.lower() in result['stdout'].lower():
                present_headers.append(header)
            else:
                missing_headers.append({'header': header, 'issue': message})
        
        return {
            'output_file': output_file,
            'present_headers': present_headers,
            'missing_headers': missing_headers,
            'raw_headers': result['stdout']
        }
    
    def run_nikto(self):
        """Run Nikto web server scanner"""
        print("\n[*] Running Nikto - Web Server Scanner...")
        
        if not self.available_tools.get('nikto'):
            return {'error': 'nikto not installed'}
        
        output_file = os.path.join(self.output_dir, f"nikto_{self.timestamp}.txt")
        command = f"nikto -h {self.target_url} -o {output_file} -Format txt"
        result = self._run_command(command, timeout=600)
        
        # Parse for critical findings
        findings = []
        if os.path.exists(output_file):
            with open(output_file, 'r') as f:
                content = f.read()
                # Look for common critical findings
                if 'OSVDB' in content:
                    findings.append("Known vulnerabilities detected - review full report")
                if 'Server leaks' in content:
                    findings.append("Information disclosure detected")
                if 'X-Frame-Options' in content:
                    findings.append("Missing X-Frame-Options header")
        
        return {
            'output_file': output_file,
            'findings': findings,
            'summary': result['stdout'][:500] if result['stdout'] else 'Check output file'
        }
    
    def run_directory_scan(self):
        """Run directory/file discovery"""
        print("\n[*] Running Directory Discovery...")
        
        results = {}
        
        # Try ffuf first (faster)
        if self.available_tools.get('ffuf'):
            print("  Using ffuf...")
            wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
            if not os.path.exists(wordlist):
                # Try common alternative locations
                wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
            
            if os.path.exists(wordlist):
                output_file = os.path.join(self.output_dir, f"ffuf_{self.timestamp}.json")
                command = f"ffuf -u {self.target_url}/FUZZ -w {wordlist} -o {output_file} -of json -s"
                result = self._run_command(command, timeout=600)
                
                results['ffuf'] = {
                    'output_file': output_file,
                    'success': result['success']
                }
            else:
                results['ffuf'] = {'error': 'Wordlist not found'}
        
        # Also try dirb if available
        if self.available_tools.get('dirb'):
            print("  Using dirb...")
            output_file = os.path.join(self.output_dir, f"dirb_{self.timestamp}.txt")
            command = f"dirb {self.target_url} -o {output_file} -S"
            result = self._run_command(command, timeout=600)
            
            results['dirb'] = {
                'output_file': output_file,
                'success': result['success']
            }
        
        return results
    
    def generate_report(self):
        """Generate a comprehensive audit report"""
        report_file = os.path.join(self.output_dir, f"security_audit_report_{self.timestamp}.json")
        
        report = {
            'target': self.target_url,
            'timestamp': self.timestamp,
            'domain': self.domain,
            'available_tools': self.available_tools,
            'results': self.results,
            'summary': {
                'total_checks': len(self.results),
                'critical_findings': [],
                'warnings': []
            }
        }
        
        # Compile critical findings and warnings
        for check, result in self.results.items():
            if isinstance(result, dict):
                if 'findings' in result and result['findings']:
                    report['summary']['critical_findings'].extend(result['findings'])
                if 'missing_headers' in result:
                    for header in result['missing_headers']:
                        report['summary']['warnings'].append(header['issue'])
                if 'cert_info' in result and 'warning' in result['cert_info']:
                    report['summary']['warnings'].append(result['cert_info']['warning'])
        
        # Save JSON report
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        # Generate human-readable summary
        summary_file = os.path.join(self.output_dir, f"security_audit_summary_{self.timestamp}.txt")
        with open(summary_file, 'w') as f:
            f.write("=" * 60 + "\n")
            f.write(f"WEB SECURITY AUDIT REPORT\n")
            f.write(f"Target: {self.target_url}\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total checks performed: {report['summary']['total_checks']}\n")
            f.write(f"Critical findings: {len(report['summary']['critical_findings'])}\n")
            f.write(f"Warnings: {len(report['summary']['warnings'])}\n\n")
            
            if report['summary']['critical_findings']:
                f.write("CRITICAL FINDINGS:\n")
                for finding in report['summary']['critical_findings']:
                    f.write(f"  ⚠️  {finding}\n")
                f.write("\n")
            
            if report['summary']['warnings']:
                f.write("WARNINGS:\n")
                for warning in report['summary']['warnings']:
                    f.write(f"  ⚡ {warning}\n")
                f.write("\n")
            
            f.write("\nDETAILED RESULTS\n")
            f.write("-" * 40 + "\n")
            for check, result in self.results.items():
                f.write(f"\n[{check.upper()}]\n")
                if isinstance(result, dict):
                    if 'error' in result:
                        f.write(f"  Error: {result['error']}\n")
                    if 'output_file' in result:
                        f.write(f"  Output file: {result['output_file']}\n")
                    if 'summary' in result:
                        f.write(f"  Summary: {result['summary'][:200]}...\n")
        
        return {
            'json_report': report_file,
            'summary_report': summary_file,
            'report_data': report
        }
    
    def run_full_audit(self):
        """Run all available security checks"""
        print("=" * 60)
        print(f"STARTING SECURITY AUDIT FOR: {self.target_url}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run all checks
        checks = [
            ('whatweb', self.run_whatweb),
            ('ssl_nmap', self.run_nmap_ssl),
            ('ssl_testssl', self.run_testssl),
            ('ssl_certificate', self.run_openssl_check),
            ('security_headers', self.run_security_headers_check),
            ('nikto', self.run_nikto),
            ('directory_discovery', self.run_directory_scan)
        ]
        
        for check_name, check_func in checks:
            try:
                self.results[check_name] = check_func()
            except Exception as e:
                self.results[check_name] = {'error': str(e)}
                print(f"[-] Error in {check_name}: {e}")
        
        # Generate report
        print("\n[*] Generating Report...")
        report = self.generate_report()
        
        print("\n" + "=" * 60)
        print("AUDIT COMPLETE")
        print("=" * 60)
        print(f"JSON Report: {report['json_report']}")
        print(f"Summary Report: {report['summary_report']}")
        print("\nSummary:")
        print(f"  - Critical findings: {len(report['report_data']['summary']['critical_findings'])}")
        print(f"  - Warnings: {len(report['report_data']['summary']['warnings'])}")
        
        return report


def main():
    parser = argparse.ArgumentParser(
        description='Web Security Audit Automation Tool',
        epilog='Example: python web_audit.py https://example.com -o results'
    )
    parser.add_argument('target', help='Target URL (e.g., https://example.com)')
    parser.add_argument('-o', '--output', default='audit_results',
                       help='Output directory (default: audit_results)')
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.target.startswith(('http://', 'https://')):
        args.target = 'https://' + args.target
    
    # Warning message
    print("\n" + "!" * 60)
    print("WARNING: Only use this tool on systems you own or have")
    print("explicit written permission to test. Unauthorized scanning")
    print("is illegal and unethical.")
    print("!" * 60 + "\n")
    
    # Run audit
    auditor = WebSecurityAuditor(args.target, args.output)
    auditor.run_full_audit()


if __name__ == "__main__":
    main()