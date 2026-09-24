# deepseek (free version)
## Prompt 1
”I am performing a security audit as part of an introductory course on cyber security. Could you please provide me with a list of commands that could be used to evaluate the security of a hosted website? Please respond in english
## Response 1

Standard recon/assessment toolkit for web app security testing. Here's what you'd actually use, organized by phase:
1. Reconnaissance

whois <domain> — ownership/registrar info
dig <domain> ANY / nslookup — DNS records, subdomains via dig axfr (zone transfer attempt)
nmap -sV -p- <target> — port scan + service version detection
curl -I <url> — response headers (check for security headers: CSP, HSTS, X-Frame-Options)
whatweb <url> — fingerprint CMS, frameworks, server tech
theHarvester -d <domain> — emails, subdomains from public sources

2. Directory/Content Discovery

gobuster dir -u <url> -w <wordlist> — brute-force hidden paths
ffuf -u <url>/FUZZ -w <wordlist> — faster fuzzing alternative

3. Vulnerability Scanning

nikto -h <url> — known misconfigurations, outdated software
nmap --script vuln <target> — NSE vuln scripts
testssl.sh <url> — TLS/SSL config weaknesses (weak ciphers, cert issues)
sslyze <url> — similar, faster

4. Manual checks with curl

Test for verbose error messages: curl <url>/nonexistent
Check HTTP methods allowed: curl -X OPTIONS -i <url>
Cookie flags (Secure, HttpOnly, SameSite): inspect Set-Cookie header

Important caveat: every one of these except passive recon (whois, dig, header checks on your own understanding) is active scanning. Running nmap/nikto/gobuster/ffuf against a site you don't own or don't have written authorization to test is illegal in basically every jurisdiction, Iceland included. For your course, use a deliberately vulnerable target — DVWA, Juice Shop, HackTheBox/TryHackMe labs — not a random live site, unless your course has an explicit authorized scope (e.g., a university-provided test server).

What's the actual target — a lab environment or something your course gave explicit authorization for? That changes which of these are appropriate to actually run.
## Prompt 2
Please put all of these into an executable python script to automate this security audit on any given website
## Response 2
I'll create a comprehensive Python script that automates these security audit tasks. The script will use subprocess to call external tools and provide a structured report.

I'll create a comprehensive Python script that automates these security audit tasks. The script will use subprocess to call external tools and provide a structured report.

(Python file provided, see attachment)

## Prompt 3
Give me a full explanation on how to use the script you gave me. For example where to specify details, and what details exactly.
## Response 3
# Complete Guide to Using the Web Security Audit Script

## 📋 Table of Contents
1. [Prerequisites & Installation](#prerequisites)
2. [Understanding the Script Structure](#structure)
3. [Step-by-Step Usage](#usage)
4. [Where to Specify Details](#specify)
5. [Understanding the Output](#output)
6. [Customization Options](#customization)
7. [Troubleshooting](#troubleshooting)

---

## 1. Prerequisites & Installation {#prerequisites}

### Step 1: Save the Script

Save the script to a file, e.g., `web_audit.py`. You can save it anywhere, but a dedicated folder is best:

```bash
mkdir ~/security_audit
cd ~/security_audit
nano web_audit.py
# Paste the script, then Ctrl+O, Enter, Ctrl+X to save
```

### Step 2: Make It Executable (Optional)

```bash
chmod +x web_audit.py
```

### Step 3: Install Required Tools

The script works with whatever tools you have installed, but for full functionality:

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y python3 python3-pip whatweb nmap nikto dirb curl openssl

# Install ffuf
sudo apt install -y ffuf

# Install testssl.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
sudo ln -s $(pwd)/testssl.sh/testssl.sh /usr/local/bin/testssl.sh
```

**Verify installations:**
```bash
which whatweb nmap nikto dirb ffuf curl openssl testssl.sh
```
Each should print a path. Missing ones will just be skipped by the script.

### Step 4: Get Wordlists (for directory discovery)

```bash
# Install SecLists (recommended)
sudo apt install -y seclists

# Or install DirBuster wordlists
sudo apt install -y dirbuster
```

---

## 2. Understanding the Script Structure {#structure}

The script has **three main components**:

| Component | Purpose |
|-----------|---------|
| `WebSecurityAuditor` class | Main engine that runs all checks |
| `main()` function | Handles command-line arguments |
| Individual `run_*` methods | Each performs a specific security check |

**The checks performed (in order):**
1. `run_whatweb()` — Identifies web technologies
2. `run_nmap_ssl()` — Enumerates SSL/TLS ciphers
3. `run_testssl()` — Deep SSL/TLS vulnerability scan
4. `run_openssl_check()` — Certificate details
5. `run_security_headers_check()` — HTTP security headers
6. `run_nikto()` — Web server vulnerability scan
7. `run_directory_scan()` — Hidden files/directories

---

## 3. Step-by-Step Usage {#usage}

### Basic Command

```bash
python3 web_audit.py <TARGET_URL>
```

### Example 1: Audit Your Own Site

```bash
python3 web_audit.py https://mysite.com
```

### Example 2: With Custom Output Directory

```bash
python3 web_audit.py https://mysite.com -o my_results
```

### Example 3: Using a Test Site (for practice)

If you want to practice on a legal target:

```bash
# These sites are designed for security testing practice
python3 web_audit.py http://testphp.vulnweb.com
python3 web_audit.py http://demo.testfire.net
```

### Example 4: Full Path Invocation

```bash
python3 /home/user/security_audit/web_audit.py https://mysite.com -o /home/user/audit_2024
```

---

## 4. Where to Specify Details {#specify}

### 🎯 Target URL — Command Line Argument

**The ONLY required input.** Specified as the first positional argument.

**Format options:**

| Input | Result |
|-------|--------|
| `https://example.com` | ✅ Correct |
| `http://example.com` | ✅ Correct |
| `example.com` | ✅ Script auto-adds `https://` |
| `https://example.com:8443` | ✅ Custom port supported |
| `https://sub.example.com/path` | ✅ Subpaths work |

**Examples:**
```bash
# Standard HTTPS site
python3 web_audit.py https://example.com

# HTTP site
python3 web_audit.py http://example.com

# Non-standard port
python3 web_audit.py https://example.com:8443

# Subdomain
python3 web_audit.py https://api.example.com
```

### 📁 Output Directory — `-o` or `--output` Flag

**Optional.** Defaults to `audit_results` in the current directory.

```bash
python3 web_audit.py https://example.com -o results_october
python3 web_audit.py https://example.com --output /tmp/audit
```

If you don't specify this, files land in `./audit_results/`.

### 🔧 Details You Might Want to Modify (in the script)

Open the script in a text editor. Here's **where and what** to change:

#### A. **Timeouts** (lines with `timeout=...`)

Located in each `run_*` method. Default is 300 seconds (5 minutes).

```python
# In run_nikto():
result = self._run_command(command, timeout=600)  # ← change 600 to adjust
```

**When to change:** Slow sites, large directories, or if scans time out.

#### B. **Wordlist Paths** (in `run_directory_scan()`)

```python
wordlist = "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
if not os.path.exists(wordlist):
    wordlist = "/usr/share/seclists/Discovery/Web-Content/common.txt"
```

**Change this if:**
- Your wordlists are in a different location
- You want a larger/smaller wordlist
- You want to use a custom wordlist

**Popular alternatives:**
```python
wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
wordlist = "/usr/share/wordlists/dirb/common.txt"
wordlist = "/path/to/your/custom-wordlist.txt"
```

#### C. **Nmap Port** (in `run_nmap_ssl()`)

```python
port = self.parsed_url.port or (443 if self.parsed_url.scheme == 'https' else 80)
```

This **auto-detects** from the URL. If your target uses a different SSL port, hardcode it:
```python
port = 8443  # ← Replace the auto-detection line
```

#### D. **WhatWeb Aggression Level** (in `run_whatweb()`)

```python
command = f"whatweb -v -a 3 {self.target_url}"
```

- `-a 1` — Stealthy (1 request)
- `-a 3` — Aggressive (default, good for audits)
- `-a 4` — Heavy (may trigger WAFs)

#### E. **Add or Remove Checks** (in `run_full_audit()`)

```python
checks = [
    ('whatweb', self.run_whatweb),
    ('ssl_nmap', self.run_nmap_ssl),
    ('ssl_testssl', self.run_testssl),
    ('ssl_certificate', self.run_openssl_check),
    ('security_headers', self.run_security_headers_check),
    ('nikto', self.run_nikto),
    ('directory_discovery', self.run_directory_scan)
]
```

**To skip a check:** Delete or comment out the line (add `#` at the start).
**To change order:** Move lines around.

#### F. **Security Headers to Check** (in `run_security_headers_check()`)

```python
headers_to_check = {
    'Strict-Transport-Security': 'HSTS not implemented',
    'Content-Security-Policy': 'CSP not implemented',
    'X-Frame-Options': 'Clickjacking protection missing',
    'X-Content-Type-Options': 'MIME sniffing protection missing',
    'Referrer-Policy': 'Referrer policy not set',
    'Permissions-Policy': 'Permissions policy not set'
}
```

**Add your own headers** by following the same pattern:
```python
'X-Custom-Header': 'Custom header missing',
```

---

## 5. Understanding the Output {#output}

After a run, you'll find files in your output directory (e.g., `audit_results/`):

```
audit_results/
├── whatweb_20241015_143022.txt          # Technology fingerprint
├── nmap_ssl_20241015_143022.txt         # SSL cipher enumeration
├── testssl_20241015_143022.txt          # Deep SSL/TLS scan
├── ssl_cert_20241015_143022.txt         # Certificate details
├── headers_20241015_143022.txt          # Raw HTTP headers
├── nikto_20241015_143022.txt            # Nikto findings
├── ffuf_20241015_143022.json            # Directory discovery (JSON)
├── dirb_20241015_143022.txt             # Directory discovery (text)
├── security_audit_report_20241015_143022.json      # ← Machine-readable
└── security_audit_summary_20241015_143022.txt      # ← Human-readable ⭐
```

### 🏆 Start With: `security_audit_summary_*.txt`

This is the easiest to read. Example:

```
============================================================
WEB SECURITY AUDIT REPORT
Target: https://example.com
Date: 2024-10-15 14:32:45
============================================================

EXECUTIVE SUMMARY
----------------------------------------
Total checks performed: 7
Critical findings: 2
Warnings: 4

CRITICAL FINDINGS:
  ⚠️  Deprecated SSL versions detected
  ⚠️  Known vulnerabilities detected - review full report

WARNINGS:
  ⚡ CSP not implemented
  ⚡ Clickjacking protection missing
  ⚡ Referrer policy not set
  ⚡ Permissions policy not set

DETAILED RESULTS
----------------------------------------

[WHATWEB]
  Output file: audit_results/whatweb_20241015_143022.txt
  Summary: https://example.com [200 OK] Apache[2.4.41], ...

[NIKTO]
  Output file: audit_results/nikto_20241015_143022.txt
  ...
```

### 📊 For Automation: `security_audit_report_*.json`

Use this if you want to parse results programmatically:

```bash
cat audit_results/security_audit_report_20241015_143022.json | python3 -m json.tool
```

Structure:
```json
{
  "target": "https://example.com",
  "timestamp": "20241015_143022",
  "domain": "example.com",
  "available_tools": {"nmap": true, "nikto": true, ...},
  "results": {
    "whatweb": {"output_file": "...", "summary": "..."},
    "nikto": {"output_file": "...", "findings": [...]},
    ...
  },
  "summary": {
    "total_checks": 7,
    "critical_findings": [...],
    "warnings": [...]
  }
}
```

---

## 6. Customization Options {#customization}

### Common Customizations

**1. Only run SSL checks** — Edit `run_full_audit()`:
```python
checks = [
    ('ssl_nmap', self.run_nmap_ssl),
    ('ssl_testssl', self.run_testssl),
    ('ssl_certificate', self.run_openssl_check),
]
```

**2. Only run header checks** (fast, non-intrusive):
```python
checks = [
    ('security_headers', self.run_security_headers_check),
]
```

**3. Add your own custom check** — Add a new method:
```python
def run_robots_check(self):
    """Check robots.txt for information disclosure"""
    print("\n[*] Checking robots.txt...")
    command = f"curl -s {self.target_url}/robots.txt"
    result = self._run_command(command)
    
    output_file = os.path.join(self.output_dir, f"robots_{self.timestamp}.txt")
    with open(output_file, 'w') as f:
        f.write(result['stdout'])
    
    findings = []
    if 'Disallow:' in result['stdout']:
        findings.append("robots.txt reveals hidden paths")
    
    return {'output_file': output_file, 'findings': findings}
```

Then add to `checks` list:
```python
('robots', self.run_robots_check),
```

**4. Change the "critical findings" logic** — Modify `generate_report()` to add more rules for what counts as critical.

---

## 7. Troubleshooting {#troubleshooting}

### Problem: "Permission denied" when running script

```bash
# Fix
chmod +x web_audit.py
python3 web_audit.py https://example.com
```

### Problem: "ModuleNotFoundError"

The script uses only standard library, so this usually means you typed the filename wrong:
```bash
# Verify Python can find the file
ls -la web_audit.py
python3 web_audit.py --help
```

### Problem: All tools report "Missing"

Your `PATH` might not include `/usr/local/bin`. Check:
```bash
echo $PATH
which nmap
```

If `nmap` is found but script says missing, the `shutil.which()` call might be affected. Run the script with the full path or fix PATH.

### Problem: Nikto/testssl.sh takes forever

Increase the timeout in the specific method:
```python
result = self._run_command(command, timeout=1800)  # 30 minutes
```

Or skip it by removing from the `checks` list.

### Problem: Directory scan finds nothing

- Verify the wordlist path exists: `ls /usr/share/wordlists/`
- Check the site returns 404 for nonexistent paths (not 200 for everything)
- Increase `-a` value in ffuf or use a larger wordlist

### Problem: "URL validation" errors

The script auto-prepends `https://` if missing. If your site is HTTP-only:
```bash
python3 web_audit.py http://example.com
```

### Problem: SSL checks fail on HTTP site

Expected — the script skips SSL checks for `http://` URLs. Use `https://` or accept the skip.

---

## 🎓 Summary: Quick Reference

| What you want to do | What to do |
|---------------------|------------|
| Run the audit | `python3 web_audit.py https://site.com` |
| Specify output folder | Add `-o folder_name` |
| Change timeouts | Edit `timeout=300` in the method |
| Use a different wordlist | Edit `wordlist = "..."` in `run_directory_scan()` |
| Skip a check | Comment out its line in `run_full_audit()` |
| Read results fast | Open `security_audit_summary_*.txt` |
| Get machine-readable results | Parse `security_audit_report_*.json` |
| Add a new check | Write `run_yourcheck()` + add to `checks` list |

---

## ⚠️ Final Reminder

**Only run this against:**
- Websites you own
- Websites you have **written permission** to test
- Legal practice targets (e.g., `testphp.vulnweb.com`, `demo.testfire.net`)

Running unauthorized scans against third-party sites is **illegal** in most jurisdictions (Computer Fraud and Abuse Act in the US, Computer Misuse Act in the UK, similar laws elsewhere).

Would you like me to walk through a specific example run, or help you add a particular check (e.g., SQL injection testing, XSS detection, or a specific header check)?

## Prompt 4

I've changed the file a bit to fit my environment more. Are there any additions you would recommend I make?
+attached_file:'audit_deepseek.py'

## Response 4

# Recommended Additions to Your Audit Script

Great modifications — the snap path for SecLists and the dual `testssl`/`testssl.sh` detection are solid adaptations. Below are additions I'd recommend, grouped by priority. I'll include code snippets you can drop in.

---

## 🔴 High Priority (Biggest Impact for an Audit)

### 1. Cookie Security Flags Check

Cookies without `Secure`, `HttpOnly`, or `SameSite` are a classic finding in intro audits.

```python
def run_cookie_check(self):
    """Check cookie security flags"""
    print("\n[*] Checking Cookie Security Flags...")

    if not self.available_tools.get('curl'):
        return {'error': 'curl not installed'}

    command = f"curl -sI -L {self.target_url}"
    result = self._run_command(command)

    output_file = os.path.join(self.output_dir, f"cookies_{self.timestamp}.txt")
    with open(output_file, 'w') as f:
        f.write(result['stdout'])

    findings = []
    # Grab all Set-Cookie headers
    cookies = re.findall(r'Set-Cookie:\s*(.+)', result['stdout'], re.IGNORECASE)

    for cookie in cookies:
        name = cookie.split('=')[0].strip()
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
        'cookies_found': len(cookies)
    }
```

### 2. Dangerous HTTP Methods Check

`TRACE`, `PUT`, `DELETE` should generally not be enabled on production web servers.

```python
def run_http_methods_check(self):
    """Check for dangerous HTTP methods"""
    print("\n[*] Checking Allowed HTTP Methods...")

    if not self.available_tools.get('curl'):
        return {'error': 'curl not installed'}

    command = f"curl -sI -X OPTIONS {self.target_url} -i"
    result = self._run_command(command)

    output_file = os.path.join(self.output_dir, f"methods_{self.timestamp}.txt")
    with open(output_file, 'w') as f:
        f.write(result['stdout'])

    findings = []
    allow_match = re.search(r'Allow:\s*(.+)', result['stdout'], re.IGNORECASE)
    if allow_match:
        allowed = [m.strip().upper() for m in allow_match.group(1).split(',')]
        for dangerous in ['TRACE', 'PUT', 'DELETE', 'CONNECT']:
            if dangerous in allowed:
                findings.append(f"Dangerous HTTP method enabled: {dangerous}")
        return {
            'output_file': output_file,
            'findings': findings,
            'allowed_methods': allowed
        }

    return {'output_file': output_file, 'findings': findings, 'allowed_methods': []}
```

### 3. Sensitive File Exposure Check

Quick check for common leak files that are easy to forget.

```python
def run_sensitive_files_check(self):
    """Check for commonly exposed sensitive files"""
    print("\n[*] Checking for Exposed Sensitive Files...")

    if not self.available_tools.get('curl'):
        return {'error': 'curl not installed'}

    sensitive_paths = [
        '/.env', '/.git/config', '/.git/HEAD', '/.svn/entries',
        '/wp-config.php.bak', '/config.php.bak', '/backup.zip',
        '/.htaccess', '/phpinfo.php', '/server-status',
        '/.DS_Store', '/web.config', '/composer.json',
        '/package.json', '/.well-known/security.txt'
    ]

    findings = []
    output_file = os.path.join(self.output_dir, f"sensitive_files_{self.timestamp}.txt")

    with open(output_file, 'w') as f:
        for path in sensitive_paths:
            url = f"{self.target_url}{path}"
            cmd = f"curl -s -o /dev/null -w '%{{http_code}}' {url}"
            res = self._run_command(cmd, timeout=15)
            status = res['stdout'].strip()
            f.write(f"{status}  {url}\n")
            if status in ('200', '301', '302'):
                findings.append(f"Potentially exposed: {path} (HTTP {status})")

    return {'output_file': output_file, 'findings': findings}
```

### 4. HTTP → HTTPS Redirect Check

A site that doesn't redirect HTTP to HTTPS is a common audit finding.

```python
def run_https_redirect_check(self):
    """Verify HTTP redirects to HTTPS"""
    print("\n[*] Checking HTTP to HTTPS Redirect...")

    if not self.available_tools.get('curl'):
        return {'error': 'curl not installed'}

    http_url = self.target_url.replace('https://', 'http://', 1)
    command = f"curl -sI {http_url}"
    result = self._run_command(command)

    output_file = os.path.join(self.output_dir, f"redirect_{self.timestamp}.txt")
    with open(output_file, 'w') as f:
        f.write(result['stdout'])

    findings = []
    if '301' in result['stdout'] or '302' in result['stdout'] or '308' in result['stdout']:
        if 'https://' in result['stdout'].lower():
            return {'output_file': output_file, 'findings': [], 'status': 'redirects_to_https'}
    findings.append("HTTP does not redirect to HTTPS")

    return {'output_file': output_file, 'findings': findings}
```

### 5. Information Disclosure Headers

`Server:` and `X-Powered-By:` often leak version numbers useful to attackers.

```python
def run_info_disclosure_check(self):
    """Check for version disclosure in headers"""
    print("\n[*] Checking for Information Disclosure Headers...")

    if not self.available_tools.get('curl'):
        return {'error': 'curl not installed'}

    command = f"curl -sI -L {self.target_url}"
    result = self._run_command(command)

    output_file = os.path.join(self.output_dir, f"disclosure_{self.timestamp}.txt")
    with open(output_file, 'w') as f:
        f.write(result['stdout'])

    findings = []
    for header in ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']:
        match = re.search(rf'{header}:\s*(.+)', result['stdout'], re.IGNORECASE)
        if match:
            value = match.group(1).strip()
            # Flag if value looks like it contains a version number
            if re.search(r'\d', value):
                findings.append(f"{header} discloses version: {value}")

    return {'output_file': output_file, 'findings': findings}
```

---

## 🟡 Medium Priority (Nice Additions)

### 6. Better Severity Classification

Right now everything ends up in "critical" or "warning". For a course report, a proper severity scheme is much better. Replace the summary-building loop in `generate_report()`:

```python
SEVERITY_RULES = {
    'Heartbleed': 'HIGH',
    'VULNERABLE': 'HIGH',
    'Dangerous HTTP method': 'HIGH',
    'Potentially exposed': 'HIGH',
    'Deprecated SSL': 'HIGH',
    'Weak ciphers': 'MEDIUM',
    'missing Secure flag': 'MEDIUM',
    'missing HttpOnly': 'MEDIUM',
    'does not redirect': 'MEDIUM',
    'discloses version': 'LOW',
    'not implemented': 'LOW',
    'not set': 'LOW',
}

def _classify(self, text):
    for pattern, level in self.SEVERITY_RULES.items():
        if pattern.lower() in text.lower():
            return level
    return 'INFO'
```

Then in `generate_report()`, instead of dumping everything into two lists, build:

```python
report['summary']['findings_by_severity'] = {
    'HIGH': [], 'MEDIUM': [], 'LOW': [], 'INFO': []
}
# ...for each finding:
level = self._classify(finding)
report['summary']['findings_by_severity'][level].append(finding)
```

### 7. HTML Report Output

Easier to hand in for a course. Add a `generate_html_report()` that writes a simple `audit_report.html` with the summary tables. Example skeleton:

```python
def generate_html_report(self, report):
    html_file = os.path.join(self.output_dir, f"audit_report_{self.timestamp}.html")
    sev = report['summary']['findings_by_severity']
    colors = {'HIGH': '#dc3545', 'MEDIUM': '#fd7e14', 'LOW': '#ffc107', 'INFO': '#0dcaf0'}

    html = [f"<html><head><title>Audit - {self.target_url}</title>",
            "<style>body{font-family:sans-serif;max-width:900px;margin:2em auto;}",
            ".badge{padding:2px 8px;border-radius:4px;color:white;font-weight:bold;}",
            "table{border-collapse:collapse;width:100%;}td,th{border:1px solid #ddd;padding:6px;}</style>",
            "</head><body>",
            f"<h1>Security Audit: {self.target_url}</h1>",
            f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>"]

    for level in ['HIGH', 'MEDIUM', 'LOW', 'INFO']:
        html.append(f"<h2>{level} ({len(sev[level])})</h2>")
        if sev[level]:
            html.append("<ul>")
            for f in sev[level]:
                html.append(f"<li><span class='badge' style='background:{colors[level]}'>{level}</span> {f}</li>")
            html.append("</ul>")
        else:
            html.append("<p><em>None</em></p>")

    html.append("</body></html>")
    with open(html_file, 'w') as f:
        f.write("\n".join(html))
    return html_file
```

### 8. Config File Support

Let users specify options without editing the code. Add at startup:

```python
def _load_config(self, config_path):
    defaults = {
        'timeout': 300,
        'whatweb_aggression': 3,
        'ffuf_wordlist': None,
        'skip_checks': [],
    }
    if config_path and os.path.exists(config_path):
        with open(config_path) as f:
            defaults.update(json.load(f))
    return defaults
```

Then pass `--config audit_config.json` via argparse.

---

## 🟢 Low Priority / Polish

### 9. Replace `shell=True` with Argument Lists

Your current `_run_command` uses `shell=True`, which is a mild injection risk if the URL is untrusted. Since it's your script and you validate input, it's not urgent, but for a security tool it's good practice:

```python
def _run_command(self, command, timeout=300):
    # command is now a list
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        ...
```

Then call sites become:
```python
command = ['nmap', '-sV', '--script', 'ssl-enum-ciphers', '-p', str(port), self.domain]
```

This eliminates shell parsing issues entirely.

### 10. Quiet / Verbose Modes

Add `-q` and `-v` flags. In a course setting, a quiet mode that only shows findings is handy.

### 11. Skip Individual Checks from CLI

```python
parser.add_argument('--skip', nargs='*', default=[],
                    help='Check names to skip (e.g., nikto directory_discovery)')
```

Then in `run_full_audit()`:
```python
for check_name, check_func in checks:
    if check_name in self.skip_checks:
        print(f"[*] Skipping {check_name}")
        continue
    ...
```

### 12. Request Rate Limiting

When doing `run_directory_scan`, add a small delay between ffuf requests to be polite to the target:
```bash
ffuf -rate 50 -u ...
```
This matters for shared hosting or when you have permission to test but don't want to knock the site over.

---

## ⚠️ Issues I Noticed in Your Current Version

1. **`self.results` doesn't include the new checks yet** — you'll need to add them to the `checks` list in `run_full_audit()`.

2. **`testssl.sh` invocation** — some installs use `testssl.sh` as a shell script that must be run from its directory. If yours is symlinked to `/usr/local/bin`, you're fine. Otherwise, guard with:
   ```python
   testssl_cmd = self.available_tools.get('testssl_path', 'testssl.sh')
   ```

3. **Nikto output check** — you look for `'X-Frame-Options'` in the Nikto report, but Nikto often phrases it differently. Consider also checking `'X-Frame-Options header is not present'` or just removing that specific check since you already cover headers in `run_security_headers_check()`.

4. **The `osvdb` regex is weak** — `'OSVDB' in content` will match informational lines too. Consider checking for `'+ OSVDB'` (with the leading `+`) which is how Nikto prefixes actual findings.

---

## Suggested New `checks` List

After adding the new methods, your `run_full_audit()` should look like:

```python
checks = [
    ('whatweb', self.run_whatweb),
    ('ssl_nmap', self.run_nmap_ssl),
    ('ssl_testssl', self.run_testssl),
    ('ssl_certificate', self.run_openssl_check),
    ('security_headers', self.run_security_headers_check),
    ('cookies', self.run_cookie_check),
    ('http_methods', self.run_http_methods_check),
    ('https_redirect', self.run_https_redirect_check),
    ('info_disclosure', self.run_info_disclosure_check),
    ('sensitive_files', self.run_sensitive_files_check),
    ('nikto', self.run_nikto),
    ('directory_discovery', self.run_directory_scan),
]
```

That gives you a much more complete OWASP-flavored audit that's still appropriate for an introductory course — you can point to specific OWASP categories (A05: Security Misconfiguration, A02: Cryptographic Failures, A01: Broken Access Control via sensitive files) in your report.

Want me to combine all these additions into a single complete updated script you can run directly?

## Prompt 5

Could you give me the entire updated file with all changes? Look over it again and better it.

## Response 5

# Complete Updated Audit Script

Here is the fully integrated version with all the improvements. I've also:
- Fixed the pipe issue in the OpenSSL cert check (uses `input=` instead of shell pipes)
- Fixed a bug where `self.results` wasn't being populated for new checks
- Added proper hostname vs URL separation (some tools prefer the bare hostname)
- Added graceful Ctrl+C handling
- Added `--only`, `--skip`, `--quiet`, `--verbose`, `--rate` CLI flags
- Added HTML report output with severity-colored badges
- Replaced `shell=True` with argument lists throughout
- Improved Nikto parsing (looks for `+ ` prefixed findings)
- Better testssl.sh discovery
- Themed HTML report

```python
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
```

---

## What Changed vs. Your Version

| Area | Change |
|------|--------|
| **Safety** | No more `shell=True`. Argument lists everywhere. Removed shell pipes for the OpenSSL chain. |
| **Severity** | Findings classified HIGH / MEDIUM / LOW / INFO via `SEVERITY_RULES`. |
| **New checks** | Cookies, HTTP methods, HTTPS redirect, info disclosure, sensitive files. |
| **Reports** | JSON + text + HTML, all written per run. HTML has colored severity badges. |
| **CLI** | `--skip`, `--only`, `-q`, `-v`, `--rate`, `-c/--config`. |
| **Config file** | Optional JSON to override timeouts, wordlist, etc. |
| **Ports** | `hostname` vs `domain` correctly separated — nmap/testssl/openssl use the right form. |
| **Nikto parsing** | Only captures `+ `-prefixed lines, so you don't get informational noise. |
| **Interrupts** | `Ctrl+C` exits cleanly with a partial-results hint. |
| **Bug fix** | `findings` list from cookie/redirect/etc. now actually flows into the report. |

---

## Example Config File (`audit_config.json`)

```json
{
  "timeout": 300,
  "timeout_ssl": 900,
  "timeout_nikto": 900,
  "timeout_dirscan": 900,
  "whatweb_aggression": 3,
  "ffuf_wordlist": "/snap/seclists/current/Discovery/Web-Content/common.txt"
}
```

Use with `python3 audit_deepseek.py https://example.com -c audit_config.json`.

---

## Example Runs

```bash
# Full audit
python3 audit_deepseek.py https://example.com

# Fast pass — no heavy scanners
python3 audit_deepseek.py https://example.com --skip nikto directory_discovery ssl_testssl

# Only TLS-related checks
python3 audit_deepseek.py https://example.com --only ssl_nmap ssl_testssl ssl_certificate

# Verbose with custom output dir
python3 audit_deepseek.py https://example.com -o october_audit -v
```

## Quick Sanity Test

After saving:

```bash
python3 audit_deepseek.py --help
python3 audit_deepseek.py http://testphp.vulnweb.com -o practice_audit
```

You should see the tool-detection block, then each check running, and end up with three report files in `practice_audit/`. Open the HTML one in a browser — that's usually the nicest artifact to submit alongside your write-up.

If anything misbehaves on your system (e.g., a tool path or a specific output-parsing quirk), paste the error and I'll patch it.

## Prompt 6

Attached are my current auditing script and the outputs it gave for the latest scan. I want you to update the script, so the outputs it gives are as detailed and useful as possible. I want you to update the script, so the output includes how long the scan took. The idea for this script is to find out as much as possible about the given ip, and whatever websites may be hosted on it's ports.
+ audit_deepseek.py
+ ... (output files found in audit_results folder)

## Response 6

# Updated Script (v8) — Full File

Below is the full updated script with all the improvements. Key additions:

**New in v8:**
- **Scan timing** — total duration and per-check duration, in console, JSON, and HTML reports
- **DNS resolution** — forward, reverse, A/AAAA, and (via `dig` if available) MX/TXT/NS
- **Comprehensive port scan** — 100+ common ports scanned concurrently, with open-port list in report
- **Banner grabbing** — non-HTTP services get a banner captured
- **Every open port probed for HTTP and HTTPS**, not just a fixed list
- **Fixed Nikto parsing** — properly skips `Target Host:` / `Target Port:` metadata and strips the Perl hashref artifacts
- **Better evidence** — actual header values captured; redirect chains recorded; content hashes to dedupe pages with identical bodies
- **New checks** — CSP directive analysis, Cache-Control for sensitive responses
- **Richer reports** — service table, DNS section, port scan table, timing breakdown
- **Optional `--deep`** flag for a much wider port sweep

```python
#!/usr/bin/env python3
"""
Web Security Audit Automation Script (v8)
For educational purposes only.
Only use on systems you own or have explicit written permission to test.

What it does
------------
Discovers reachable services on the target IP (or host), then runs a set of
targeted, low-noise checks against every HTTP/HTTPS endpoint it finds:
HTTP security headers, cookie flags, CORS, HTTP methods, TLS configuration,
sensitive file exposure, HTML content analysis across discovered pages, and
optional external tools (whatweb, nikto, nmap, ffuf, dirb, testssl).
Output is JSON + text + HTML, written to a per-run folder, and includes
timing information for the overall scan and each individual check.

Design principles
-----------------
* Reachability-gated: no web finding is reported unless a real HTTP response
  was received during service discovery.
* Evidence-based: every finding carries a URL, confidence, and evidence.
* Content-length aware: a 200 with 0 bytes is not treated as an exposure.
* Tool-agnostic: each external tool is optional; missing tools are skipped.
* Safe on unknown targets: paths, checks, and page discovery are generic.

Changes in v8 (over v7)
-----------------------
* Scan duration tracked per check and overall; shown in console, text report,
  JSON, and HTML.
* DNS resolution: forward, reverse, and (via dig, if installed) MX/TXT/NS.
* Concurrent TCP port scan of 100+ common ports; optionally --deep for a
  wider sweep. Every open port is probed for HTTP and HTTPS.
* Non-HTTP services get a best-effort banner grab.
* Nikto parsing fixed: metadata lines like "Target Host:" are skipped, and
  Perl hashref artifacts (HASH(0x...)) are stripped from titles.
* Page analysis deduplicates by content hash, avoiding duplicate findings
  from / and /index.php returning identical bodies.
* New checks: CSP directive analysis (unsafe-inline / unsafe-eval / wildcards)
  and Cache-Control review for responses carrying sensitive data.
* Evidence quality improved: present header values captured, redirect chains
  recorded.
* Reports include a service table, port scan table, DNS section, and a
  per-check timing breakdown.

Usage
-----
    python3 audit_deepseek.py https://example.com
    python3 audit_deepseek.py 192.0.2.10 --ports 80,443,8080
    python3 audit_deepseek.py 192.0.2.10 --deep
    python3 audit_deepseek.py https://example.com -o results --skip nikto directory_discovery
    python3 audit_deepseek.py https://example.com --only security_headers cookies
    python3 audit_deepseek.py https://example.com --flat
"""

import argparse
import hashlib
import html
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_RULES = [
    ('Heartbleed', 'HIGH'),
    ('VULNERABLE', 'HIGH'),
    ('Dangerous HTTP method', 'HIGH'),
    ('Deprecated SSL', 'HIGH'),
    ('Weak ciphers', 'HIGH'),
    ('does not redirect to HTTPS', 'HIGH'),
    ('expired', 'HIGH'),
    ('XSS payload', 'HIGH'),
    ('CORS wildcard origin with credentials', 'HIGH'),
    ('CORS reflects arbitrary Origin', 'HIGH'),
    ('admin login', 'MEDIUM'),
    ('config.php', 'MEDIUM'),
    ('config file', 'MEDIUM'),
    ('Server error on path', 'MEDIUM'),
    ('without the httponly', 'MEDIUM'),
    ('POST form without CSRF', 'MEDIUM'),
    ('missing Secure flag', 'MEDIUM'),
    ('missing HttpOnly flag', 'MEDIUM'),
    ('missing SameSite', 'MEDIUM'),
    ('Self-signed certificate', 'MEDIUM'),
    ('expires in', 'MEDIUM'),
    ('unsafe-inline', 'MEDIUM'),
    ('unsafe-eval', 'MEDIUM'),
    ('No Cache-Control', 'MEDIUM'),
    ('DEBUG', 'LOW'),
    ('anti-clickjacking', 'LOW'),
    ('discloses version', 'LOW'),
    ('not implemented', 'LOW'),
    ('not set', 'LOW'),
    ('protection missing', 'LOW'),
    ('leaks inodes', 'LOW'),
]

SECURITY_HEADERS = {
    'Strict-Transport-Security': 'HSTS not implemented',
    'Content-Security-Policy':   'CSP not implemented',
    'X-Frame-Options':           'Clickjacking protection missing',
    'X-Content-Type-Options':    'MIME sniffing protection missing',
    'Referrer-Policy':           'Referrer policy not set',
    'Permissions-Policy':        'Permissions policy not set',
}

INFORMATIONAL_HEADERS = {
    'Cross-Origin-Opener-Policy':   'COOP not set',
    'Cross-Origin-Resource-Policy': 'CORP not set',
}

SENSITIVE_PATHS = [
    '/.env', '/.env.bak', '/.env.local', '/.env.production',
    '/.git/config', '/.git/HEAD', '/.gitignore', '/.svn/entries',
    '/config.php', '/config.inc.php', '/config.php.bak', '/config.php~',
    '/config.old', '/config.sample.php', '/configuration.php',
    '/includes/config.php', '/includes/db.php', '/includes/database.php',
    '/includes/config.inc.php', '/db.php', '/database.php',
    '/wp-config.php', '/wp-config.php.bak', '/settings.php',
    '/backup.zip', '/backup.tar.gz', '/backup.sql', '/dump.sql',
    '/db.sql', '/database.sql',
    '/.htaccess', '/.htpasswd', '/server-status', '/server-info',
    '/phpinfo.php', '/info.php', '/test.php', '/.DS_Store',
    '/web.config', '/composer.json', '/composer.lock',
    '/package.json', '/package-lock.json', '/.editorconfig',
    '/robots.txt', '/sitemap.xml', '/.well-known/security.txt',
    '/swagger.json', '/openapi.json', '/api-docs',
    '/uploads/', '/upload/', '/files/', '/tmp/',
]

WORDLIST_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/snap/seclists/current/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-small.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
]

# A broad but bounded port list. Deliberately wider than v7 so an audit of a
# single IP surfaces services the operator may have forgotten about.
COMMON_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 111, 135, 139, 143, 161, 162, 389,
    443, 445, 465, 514, 587, 631, 636, 873, 990, 993, 995,
    1080, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087, 2095, 2096,
    2181, 2222, 2375, 2376, 3000, 3128, 3260, 3306, 3389,
    4443, 4444, 5000, 5432, 5555, 5601, 5672, 5900, 5984, 5985, 5986,
    6379, 6443, 7001, 7077, 7443, 8000, 8008, 8009, 8080, 8081, 8086, 8088,
    8090, 8161, 8200, 8443, 8500, 8529, 8834, 8880, 8888, 8983, 9000, 9042,
    9090, 9092, 9200, 9300, 9443, 9999, 10000, 10250, 11211, 15672,
    27017, 27018, 50000, 50070, 61616,
]

# Extra ports for --deep: a partial top-1000 sweep. Kept as a curated subset
# rather than a literal 1-1000 loop to keep runtime predictable.
DEEP_PORTS = COMMON_PORTS + [
    7, 9, 13, 26, 37, 79, 88, 106, 113, 119, 144, 179, 199, 427, 444, 513,
    515, 543, 544, 548, 554, 646, 1025, 1026, 1027, 1028, 1029, 1110, 1720,
    1755, 1900, 2000, 2001, 2121, 2717, 3986, 4899, 5009, 5051, 5060, 5101,
    5190, 5357, 5631, 5666, 5800, 5901, 6000, 6001, 6646, 7070, 8001, 8002,
    8444, 8830, 8889, 8999, 9001, 9002, 9080, 9091, 9100, 9500, 10001,
    15671, 32768, 49152, 49153, 49154, 49155, 49156, 49157,
]

FALLBACK_PAGE_PATHS = [
    '/login', '/login.php', '/signin',
    '/register', '/register.php', '/signup',
    '/admin', '/admin/', '/dashboard', '/account',
]

BODY_SNIPPET_SIZE = 16384
PROBE_TIMEOUT = 10


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def _sanitize_path_component(text):
    if not text:
        return 'unknown'
    if '://' in text:
        text = text.split('://', 1)[1]
    text = text.split('/', 1)[0]
    text = re.sub(r'[^A-Za-z0-9._-]+', '_', text)
    return (text.strip('._-') or 'unknown')[:80]


def _service_tag(url):
    return (url.replace('://', '_').replace(':', '_').replace('/', '_'))[:120]


def _format_duration(seconds):
    if seconds is None:
        return 'n/a'
    if seconds < 1:
        return f"{seconds * 1000:.0f}ms"
    if seconds < 60:
        return f"{seconds:.2f}s"
    minutes, sec = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m {sec}s"


def _is_ip_literal(text):
    try:
        socket.inet_aton(text)
        return True
    except (socket.error, OSError):
        pass
    try:
        socket.inet_pton(socket.AF_INET6, text)
        return True
    except (socket.error, OSError):
        return False


# ---------------------------------------------------------------------------
# Auditor
# ---------------------------------------------------------------------------

class WebSecurityAuditor:

    def __init__(self, target_url, output_dir="audit_results",
                 config=None, skip_checks=None, only_checks=None,
                 quiet=False, verbose=False, rate=50, ports=None,
                 flat_output=False, deep=False):
        self.target_url = target_url.rstrip('/')
        parsed = urlparse(self.target_url)
        self.hostname = parsed.hostname
        self.domain = parsed.netloc
        self.explicit_ports = [int(p) for p in ports] if ports else None

        # Populated during the run
        self.services = []              # HTTP/HTTPS endpoints
        self.other_services = []        # open non-HTTP ports with banner
        self.open_ports = []            # all open ports
        self.primary_url = self.target_url
        self.results = {}

        # Timing
        self.scan_start = None
        self.scan_end = None

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
        self.deep = deep

        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        base = os.path.abspath(output_dir)
        if flat_output:
            self.output_dir = base
        else:
            label = f"run_{self.timestamp}_{_sanitize_path_component(self.domain)}"
            self.output_dir = os.path.join(base, label)
        os.makedirs(self.output_dir, exist_ok=True)

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
        tools = ['whatweb', 'nmap', 'nikto', 'dirb', 'ffuf',
                 'openssl', 'curl', 'dig']
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
        path = os.path.join(self.output_dir, f"{name}.txt")
        with open(path, 'w', encoding='utf-8', errors='replace') as f:
            f.write(content or '')
        return path

    # ---------------------------------------------------------- findings

    def _classify(self, text):
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
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                return s.connect_ex((host, port)) == 0
        except Exception:
            return False

    def _scan_ports(self, ports, timeout=1.0, workers=100):
        """Concurrent TCP connect scan. Returns sorted list of open ports."""
        def check_one(port):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(timeout)
                    if s.connect_ex((self.hostname, port)) == 0:
                        return port
            except Exception:
                pass
            return None

        ports = sorted(set(int(p) for p in ports))
        open_ports = []
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(check_one, p): p for p in ports}
            for fut in as_completed(futures):
                try:
                    r = fut.result()
                    if r is not None:
                        open_ports.append(r)
                except Exception:
                    pass
        return sorted(open_ports)

    def _banner_grab(self, port, timeout=2.0):
        """Best-effort banner capture for non-HTTP services."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((self.hostname, port))
                # Ask nicely for a banner (harmless for HTTP; ignored by most
                # other protocols).
                try:
                    s.sendall(b"\r\n")
                except Exception:
                    pass
                s.settimeout(timeout)
                try:
                    data = s.recv(512)
                    if not data:
                        return None
                    text = data.decode('utf-8', errors='replace').strip()
                    # Strip terminal escape codes that some services send.
                    text = re.sub(r'\x1b\[[0-9;]*[A-Za-z]', '', text)
                    return text[:200] or None
                except socket.timeout:
                    return None
        except Exception:
            return None

    def _probe_http(self, url, timeout=None):
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
            '-A', 'Mozilla/5.0 (compatible; WebAudit/8.0)',
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

    def _candidate_urls(self, open_ports):
        """Ordered URLs to try during service discovery.

        Starts with the explicit target, then every open port we found.
        HTTPS before HTTP when both are ambiguous, since that is the
        common case for real deployments.
        """
        urls = [self.target_url]
        seen = {self.target_url}

        host = self.hostname
        tport = urlparse(self.target_url).port or (
            443 if self.target_url.startswith('https://') else 80)
        alt_scheme = 'http' if self.target_url.startswith('https://') else 'https'

        alt = f"{alt_scheme}://{host}:{tport}"
        if alt not in seen:
            urls.append(alt); seen.add(alt)

        for p in open_ports:
            if p == tport:
                continue
            for sch in ('https', 'http'):
                u = f"{sch}://{host}:{p}"
                if u not in seen:
                    urls.append(u); seen.add(u)
        return urls

    def run_service_discovery(self):
        self._log("\n[*] Service Discovery")
        port_scan_start = time.time()

        # Assemble port list.
        ports = set(COMMON_PORTS)
        if self.deep:
            ports.update(DEEP_PORTS)
        if self.explicit_ports:
            ports.update(self.explicit_ports)
        ports.update(int(p) for p in self.extra_ports if p)

        # Make sure the target's own port is included so we do not skip it.
        tport = urlparse(self.target_url).port or (
            443 if self.target_url.startswith('https://') else 80)
        ports.add(tport)

        self._log(f"    scanning {len(ports)} port(s)...")
        self.open_ports = self._scan_ports(list(ports))
        port_scan_elapsed = time.time() - port_scan_start

        self._log(f"    open ports ({len(self.open_ports)}): "
                  f"{self.open_ports} "
                  f"[{_format_duration(port_scan_elapsed)}]")

        # Probe each open port for HTTP/HTTPS.
        candidates = self._candidate_urls(self.open_ports)
        self._vlog(f"    candidate URLs: {candidates}")

        seen_keys = set()
        http_port_set = set()
        for url in candidates:
            resp = self._probe_http(url)
            if not resp:
                continue
            key = (resp['scheme'], resp['port'])
            if key in seen_keys:
                continue
            seen_keys.add(key)
            http_port_set.add(resp['port'])
            self.services.append(resp)
            self._log(f"    [+] {url} -> HTTP {resp['status']} "
                      f"({resp['content_type'] or 'no content-type'})")

        # Banner-grab any remaining open ports (non-HTTP services).
        for port in self.open_ports:
            if port in http_port_set:
                continue
            banner = self._banner_grab(port)
            self.other_services.append({'port': port, 'banner': banner})
            if banner:
                self._log(f"    [~] port {port}: {banner[:60]}")
            else:
                self._log(f"    [~] port {port}: open (no banner)")

        if self.services:
            self.primary_url = self.services[0]['url']

        findings = []
        if not self.services:
            findings.append(self._finding(
                "No reachable web service found", severity='INFO',
                evidence=(f"Scanned {len(ports)} ports; "
                          f"{len(self.open_ports)} open; no HTTP/HTTPS response"),
                confidence='confirmed', check='service_discovery'))
        elif not any(s['url'] == self.target_url for s in self.services):
            findings.append(self._finding(
                "Original target URL did not respond; audit redirected to a "
                "discovered service", severity='INFO',
                evidence=f"Using {self.primary_url}",
                url=self.primary_url, confidence='confirmed',
                check='service_discovery'))

        # Report unexpected open ports (potentially interesting).
        for svc in self.other_services:
            findings.append(self._finding(
                f"Non-HTTP service on port {svc['port']}"
                + (f": {svc['banner'][:80]}" if svc['banner'] else ""),
                severity='INFO',
                evidence=f"TCP port {svc['port']} is open",
                confidence='confirmed', check='service_discovery'))

        return {
            'candidates_probed': len(candidates),
            'ports_scanned': len(ports),
            'port_scan_seconds': port_scan_elapsed,
            'open_ports': self.open_ports,
            'non_http_services': self.other_services,
            'confirmed_services': [
                {'url': s['url'], 'scheme': s['scheme'], 'port': s['port'],
                 'status': s['status'],
                 'server': (s['headers'].get('server') or [''])[0],
                 'content_type': s['content_type']}
                for s in self.services
            ],
            'findings': findings,
            'summary': (f"{len(self.services)} HTTP/HTTPS service(s) confirmed, "
                        f"{len(self.other_services)} other open port(s)"
                        if self.services else
                        "No reachable web service confirmed"),
        }

    # --------------------------------------------------------------- DNS

    def run_dns_info(self):
        """Resolve the target and gather what we can about it via DNS."""
        self._log("\n[*] DNS / Host Resolution")
        info = {
            'input': self.hostname,
            'is_ip_literal': _is_ip_literal(self.hostname),
        }
        findings = []

        # Forward resolution.
        try:
            results = socket.getaddrinfo(self.hostname, None)
            ips = sorted({r[4][0] for r in results})
            info['resolved_ips'] = ips
        except socket.gaierror as e:
            info['resolved_ips'] = []
            info['forward_error'] = str(e)
            findings.append(self._finding(
                f"DNS resolution failed: {e}", severity='INFO',
                evidence=f"Could not resolve {self.hostname}",
                confidence='confirmed', check='dns_info'))

        primary_ip = info['resolved_ips'][0] if info.get('resolved_ips') else None

        # Reverse DNS on the primary IP.
        if primary_ip:
            try:
                host, aliases, _ = socket.gethostbyaddr(primary_ip)
                info['reverse_dns'] = host
                info['reverse_aliases'] = aliases
            except (socket.herror, socket.gaierror):
                info['reverse_dns'] = None

        # Optional: dig for MX/TXT/NS/CNAME.
        if self.available_tools.get('dig') and not info['is_ip_literal']:
            for rtype in ('MX', 'TXT', 'NS', 'CNAME'):
                r = self._run_command(
                    ['dig', '+short', rtype, self.hostname], timeout=6)
                val = (r['stdout'] or '').strip()
                if val:
                    info[f'dns_{rtype.lower()}'] = val.splitlines()[:15]

        # Findings from what we learned.
        if primary_ip and not info['is_ip_literal']:
            findings.append(self._finding(
                f"Host resolves to {', '.join(info['resolved_ips'][:4])}",
                severity='INFO', evidence=f"{self.hostname} -> {primary_ip}",
                url=self.target_url, check='dns_info'))

        if info.get('reverse_dns') and info['is_ip_literal']:
            findings.append(self._finding(
                f"Reverse DNS: {info['reverse_dns']}", severity='INFO',
                evidence=f"{primary_ip} -> {info['reverse_dns']}",
                url=self.target_url, check='dns_info'))

        # Output file.
        out_file = self._write('dns_info', json.dumps(info, indent=2, default=str))
        return {'output_file': out_file, 'dns_info': info, 'findings': findings}

    # -------------------------------------------------------- HTML analysis

    def _analyze_html(self, url, body, check_name):
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

        # <meta> tags — useful for finding CSP-in-meta, referrer, etc.
        for m in re.finditer(r'<meta\b([^>]*)>', body, re.IGNORECASE):
            attrs = m.group(1)
            name_m = re.search(r'(?:name|http-equiv)\s*=\s*["\']([^"\']+)["\']',
                               attrs, re.IGNORECASE)
            content_m = re.search(r'content\s*=\s*["\']([^"\']*)["\']',
                                  attrs, re.IGNORECASE)
            if name_m and content_m:
                findings.append(self._finding(
                    f"Meta {name_m.group(1)}: {content_m.group(1)[:120]}",
                    severity='INFO', evidence=url, url=url, check=check_name))

        # Forms (with CSRF audit for POST forms)
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

        # Input fields
        inputs = sorted({m.group(1) for m in re.finditer(
            r'<input\b[^>]*\bname\s*=\s*["\']([^"\']+)["\']',
            body, re.IGNORECASE)})
        if inputs:
            findings.append(self._finding(
                f"Input fields: {', '.join(inputs)}", severity='INFO',
                evidence=url, url=url, check=check_name))

        # <script src>
        script_srcs = sorted({m.group(1) for m in re.finditer(
            r'<script\b[^>]*\bsrc\s*=\s*["\']([^"\']+)["\']',
            body, re.IGNORECASE)})
        for src in script_srcs:
            findings.append(self._finding(
                f"Script loaded: {src}", severity='INFO',
                evidence=url, url=url, check=check_name))

        # Interesting <a href>
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

        # HTML comments
        comments = [re.sub(r'\s+', ' ', c).strip()
                    for c in re.findall(r'<!--(.*?)-->', body, re.DOTALL)]
        comments = [c for c in comments if len(c) >= 10]
        if comments:
            findings.append(self._finding(
                f"HTML comments present ({len(comments)})", severity='INFO',
                evidence=' | '.join(comments[:3])[:400],
                url=url, check=check_name))

        # Unescaped <script> with alert()/document.cookie -> potential XSS.
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
        root = svc['url'].rstrip('/')
        parsed_root = urlparse(root)
        body = svc.get('body_snippet') or ''
        hrefs = re.findall(r'<a\b[^>]*\bhref\s*=\s*["\']([^"\']+)["\']',
                           body, re.IGNORECASE)

        asset_re = re.compile(
            r'\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|pdf|zip|tar|gz|mp4|webm)'
            r'(\?|$)', re.IGNORECASE)

        urls, seen = [], {root, root + '/'}
        for h in hrefs:
            if h.startswith(('mailto:', 'javascript:', 'tel:', 'data:', '#')):
                continue
            full = urljoin(root + '/', h).split('#', 1)[0]
            if urlparse(full).netloc != parsed_root.netloc:
                continue
            if asset_re.search(full) or full in seen:
                continue
            seen.add(full)
            urls.append(full)

        priority = ('login', 'signin', 'register', 'signup', 'admin',
                    'dashboard', 'account', 'profile')
        urls.sort(key=lambda u: 0 if any(k in u.lower() for k in priority) else 1)

        if not urls:
            urls = [root + p for p in FALLBACK_PAGE_PATHS]

        return urls[:cap]

    # ------------------------------------------------------------- checks

    def run_body_analysis_check(self):
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
        """Fetch discovered sub-pages, deduplicating identical bodies."""
        self._log("\n[*] Multi-Page Content Analysis")
        err = self._preflight('page_analysis')
        if err: return err

        findings, first_file = [], None
        pages_fetched = []
        seen_hashes = set()

        # Seed with root page hashes so /index.php isn't re-analyzed when it
        # matches /.
        for svc in self.services:
            body = svc.get('body_snippet') or ''
            if body:
                seen_hashes.add(hashlib.md5(body.encode()).hexdigest())

        for svc in self.services:
            for url in self._discover_pages(svc):
                resp = self._probe_http(url)
                if not resp:
                    continue

                body = resp.get('body_snippet') or ''
                body_hash = hashlib.md5(body.encode()).hexdigest() if body else None
                duplicate = body_hash and body_hash in seen_hashes
                if body_hash:
                    seen_hashes.add(body_hash)

                pages_fetched.append({
                    'url': url, 'status': resp['status'],
                    'size': resp['size'], 'duplicate': bool(duplicate),
                })

                if duplicate:
                    continue

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
                    value = '; '.join(hdrs[header.lower()])
                    present_all.append({'header': header, 'url': svc['url'],
                                        'value': value})
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
            'present_headers': present_all,
            'missing_headers': missing_all,
            'findings': findings,
            'raw_headers': raw_headers,
        }

    def run_csp_analysis_check(self):
        """Inspect CSP directives for known weaknesses."""
        self._log("\n[*] CSP Policy Analysis")
        err = self._preflight('csp_analysis')
        if err: return err

        findings, first_file = [], None
        for svc in self.services:
            csp = '; '.join(svc['headers'].get('content-security-policy', []))
            if not csp:
                continue
            if first_file is None:
                first_file = self._write('csp', csp)

            if "'unsafe-inline'" in csp:
                findings.append(self._finding(
                    "CSP allows 'unsafe-inline'", severity='MEDIUM',
                    evidence=csp[:200], url=svc['url'], check='csp_analysis'))
            if "'unsafe-eval'" in csp:
                findings.append(self._finding(
                    "CSP allows 'unsafe-eval'", severity='MEDIUM',
                    evidence=csp[:200], url=svc['url'], check='csp_analysis'))
            if re.search(r'\b\*\b', csp):
                findings.append(self._finding(
                    "CSP contains wildcard source (*)", severity='LOW',
                    evidence=csp[:200], url=svc['url'], check='csp_analysis'))
            if 'object-src' not in csp:
                findings.append(self._finding(
                    "CSP missing object-src directive", severity='LOW',
                    evidence=csp[:200], url=svc['url'], check='csp_analysis'))

        return {'output_file': first_file, 'findings': findings}

    def run_cache_control_check(self):
        """Flag sensitive-looking responses without Cache-Control: no-store."""
        self._log("\n[*] Cache-Control Review")
        err = self._preflight('cache_control')
        if err: return err

        findings, first_file = [], None
        for svc in self.services:
            if first_file is None:
                first_file = self._write('cache_control', svc['headers_raw'])
            cache = '; '.join(svc['headers'].get('cache-control', [])).lower()
            if not cache:
                findings.append(self._finding(
                    "No Cache-Control header on response", severity='LOW',
                    evidence=f"{svc['url']} returned no Cache-Control header",
                    url=svc['url'], check='cache_control'))
            elif 'no-store' not in cache and 'private' not in cache:
                findings.append(self._finding(
                    "Cache-Control permits shared caching",
                    severity='LOW',
                    evidence=f"Cache-Control: {cache}",
                    url=svc['url'], check='cache_control'))
        return {'output_file': first_file, 'findings': findings}

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
                    '-A', 'Mozilla/5.0 (compatible; WebAudit/8.0)', svc['url']]
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
                    '-A', 'Mozilla/5.0 (compatible; WebAudit/8.0)', svc['url']]
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
                            '-A', 'Mozilla/5.0 (compatible; WebAudit/8.0)',
                            url]
                    res = self._run_command(args, timeout=12)
                    raw = res['stdout'].strip()
                    code, size = raw.split('|', 1) if '|' in raw else (raw, '0')
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
                    elif code in ('401', '403'):
                        findings.append(self._finding(
                            f"Protected path exists: {path} (HTTP {code})",
                            severity='INFO',
                            evidence=f"{url} returned HTTP {code}",
                            url=url, check='sensitive_files'))

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

        first_file, findings = None, []
        for svc in self.services:
            result = self._run_command(
                ['whatweb', '--color=never', '-a3', svc['url']], timeout=60)
            out = result['stdout'] or result['stderr']
            if first_file is None:
                first_file = self._write('whatweb', out)

            # WhatWeb output is one line per URL like:
            #   http://x [200 OK] Apache[2.4.58], Cookies[PHPSESSID], Title[...]
            for line in out.splitlines():
                m = re.match(r'^(\S+)\s+\[([^\]]+)\]\s+(.+)$', line)
                if m:
                    url, status, plugins = m.group(1), m.group(2), m.group(3)
                    findings.append(self._finding(
                        f"WhatWeb {url} [{status}]: {plugins[:200]}",
                        severity='INFO', evidence=url, url=url,
                        check='whatweb'))

        return {'output_file': first_file, 'findings': findings}

    def run_nikto(self):
        """Run Nikto and keep every meaningful '+ ' finding line."""
        self._log("\n[*] Nikto - Web Server Scanner")
        err = self._preflight('nikto', required_tool='nikto')
        if err: return err

        # Metadata/status lines we never want as findings.
        skip = re.compile(
            r'^(target\s+(ip|host|hostname|port)|start\s*time|end\s*time|'
            r'server\s*:|no\s+cgi\s+directories|root\s+page\s+/|'
            r'\d+\s+host\(s\)\s+tested|'
            r'nikto\s+v)',
            re.IGNORECASE)

        # Perl hashref artifacts Nikto occasionally emits under load.
        hashref = re.compile(r'\bHASH\(0x[0-9a-fA-F]+\)')

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
                    if skip.match(text):
                        continue
                    # Strip the occasional Perl hashref from the line.
                    text = hashref.sub('', text).strip()
                    if not text:
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
        result = self._run_command(['ffuf', '-h'], timeout=5)
        haystack = (result['stdout'] + result['stderr']).lower()
        if '-rate' in haystack:
            return ['-rate', str(self.rate)]
        delay = 1.0 / max(self.rate, 1)
        return ['-p', f'{delay:.3f}', '-t', '10']

    def run_directory_scan(self):
        self._log("\n[*] Directory Discovery")
        err = self._preflight('directory_discovery')
        if err: return err

        results = {}

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
        total_duration = (
            (self.scan_end or time.time()) - (self.scan_start or time.time())
        )
        report = {
            'target': self.target_url,
            'timestamp': self.timestamp,
            'domain': self.domain,
            'run_directory': self.output_dir,
            'scan_duration_seconds': total_duration,
            'scan_duration_human': _format_duration(total_duration),
            'available_tools': {k: v for k, v in self.available_tools.items()
                                if k != 'testssl_path'},
            'services': [
                {'url': s['url'], 'scheme': s['scheme'], 'port': s['port'],
                 'status': s['status'],
                 'server': (s['headers'].get('server') or [''])[0],
                 'content_type': s['content_type']}
                for s in self.services
            ],
            'open_ports': self.open_ports,
            'non_http_services': self.other_services,
            'results': self.results,
            'check_durations': {
                name: round(r.get('_duration_seconds', 0), 3)
                for name, r in self.results.items()
                if isinstance(r, dict)
            },
            'summary': {
                'total_checks': len(self.results),
                'web_service_reachable': bool(self.services),
                'open_port_count': len(self.open_ports),
                'findings_by_severity': {k: [] for k in
                                         ('HIGH', 'MEDIUM', 'LOW', 'INFO')},
            },
        }

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
            f.write(f"Target:        {report['target']}\n")
            f.write(f"Date:          "
                    f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan duration: {report.get('scan_duration_human', 'n/a')} "
                    f"({report.get('scan_duration_seconds', 0):.1f}s)\n")
            f.write(f"Run:           {report.get('run_directory', '')}\n")
            f.write("=" * 70 + "\n\n")

            f.write("EXECUTIVE SUMMARY\n" + "-" * 70 + "\n")
            f.write(f"Checks performed      : {report['summary']['total_checks']}\n")
            f.write(f"Web service reachable : "
                    f"{'yes' if report['summary']['web_service_reachable'] else 'no'}\n")
            f.write(f"Open ports            : {report['summary']['open_port_count']}\n")
            for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
                f.write(f"{level:<22}: {len(sev[level])}\n")
            f.write("\n")

            # Services table
            if report.get('services'):
                f.write("CONFIRMED WEB SERVICES\n" + "-" * 70 + "\n")
                for svc in report['services']:
                    f.write(f"  {svc['url']}  HTTP {svc['status']}  "
                            f"{svc.get('server') or ''}\n")
                f.write("\n")

            if report.get('open_ports'):
                f.write("OPEN PORTS\n" + "-" * 70 + "\n")
                f.write(f"  {report['open_ports']}\n\n")

            if report.get('non_http_services'):
                f.write("NON-HTTP SERVICES\n" + "-" * 70 + "\n")
                for svc in report['non_http_services']:
                    banner = svc.get('banner') or '(no banner)'
                    f.write(f"  port {svc['port']}: {banner[:100]}\n")
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

            f.write("\nCHECK TIMINGS\n" + "-" * 70 + "\n")
            for name, dur in sorted(report.get('check_durations', {}).items(),
                                    key=lambda kv: -kv[1]):
                f.write(f"  {name:<22} {_format_duration(dur)}\n")
            f.write("\n")

            f.write("\nDETAILED RESULTS\n" + "-" * 70 + "\n")
            for check, result in self.results.items():
                dur = ''
                if isinstance(result, dict) and '_duration_seconds' in result:
                    dur = f" ({_format_duration(result['_duration_seconds'])})"
                f.write(f"\n[{check.upper()}]{dur}\n")
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
            "table.svc{border-collapse:collapse;width:100%;}",
            "table.svc td,table.svc th{border:1px solid #ddd;padding:6px;",
            "text-align:left;font-size:.9em;}",
            "</style></head><body>",
            "<h1>Security Audit Report</h1>",
            f"<p class='meta'><b>Target:</b> {e(report['target'])}<br>",
            f"<b>Web service reachable:</b> "
            f"{'yes' if report['summary']['web_service_reachable'] else 'no'}<br>",
            f"<b>Open ports:</b> {report['summary']['open_port_count']}<br>",
            f"<b>Scan duration:</b> "
            f"{e(report.get('scan_duration_human', 'n/a'))} "
            f"({report.get('scan_duration_seconds', 0):.1f}s)<br>",
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

        # Services table
        if report.get('services'):
            parts.append("<h2>Confirmed Web Services</h2>")
            parts.append("<table class='svc'>")
            parts.append("<tr><th>URL</th><th>Status</th><th>Server</th>"
                         "<th>Content-Type</th></tr>")
            for svc in report['services']:
                parts.append(
                    f"<tr><td><code>{e(svc['url'])}</code></td>"
                    f"<td>{svc['status']}</td>"
                    f"<td>{e(svc.get('server') or '')}</td>"
                    f"<td>{e(svc.get('content_type') or '')}</td></tr>")
            parts.append("</table>")

        # Non-HTTP services
        if report.get('non_http_services'):
            parts.append("<h2>Non-HTTP Services</h2>")
            parts.append("<table class='svc'>")
            parts.append("<tr><th>Port</th><th>Banner</th></tr>")
            for svc in report['non_http_services']:
                parts.append(
                    f"<tr><td>{svc['port']}</td>"
                    f"<td>{e((svc.get('banner') or '')[:120])}</td></tr>")
            parts.append("</table>")

        # DNS
        dns = self.results.get('dns_info', {}).get('dns_info', {})
        if dns:
            parts.append("<h2>DNS / Host Resolution</h2>")
            parts.append("<ul>")
            for k in ('input', 'is_ip_literal', 'resolved_ips',
                      'reverse_dns'):
                if k in dns and dns[k]:
                    parts.append(f"<li><b>{e(k)}:</b> {e(str(dns[k]))}</li>")
            for k in list(dns.keys()):
                if k.startswith('dns_') and dns[k]:
                    parts.append(f"<li><b>{e(k)}:</b> {e(str(dns[k]))}</li>")
            parts.append("</ul>")

        # Findings by severity
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

        # Per-check timings
        parts.append("<h2>Check Timings</h2>")
        parts.append("<table class='svc'>")
        parts.append("<tr><th>Check</th><th>Duration</th></tr>")
        for name, dur in sorted(report.get('check_durations', {}).items(),
                                key=lambda kv: -kv[1]):
            parts.append(f"<tr><td>{e(name)}</td>"
                         f"<td>{e(_format_duration(dur))}</td></tr>")
        parts.append("</table>")

        # Detailed results
        parts.append("<h2>Detailed Results</h2>")
        for check, result in self.results.items():
            dur_html = ''
            if isinstance(result, dict) and '_duration_seconds' in result:
                dur_html = (f" <span class='conf'>"
                            f"({e(_format_duration(result['_duration_seconds']))})"
                            f"</span>")
            parts.append(f"<div class='check'><b>{e(check)}</b>{dur_html}<br>")
            if not isinstance(result, dict):
                parts.append(f"{e(str(result))}</div>")
                continue
            if result.get('error'):
                parts.append(f"<i>Error:</i> {e(str(result['error']))}<br>")
            if result.get('output_file'):
                parts.append(f"<i>Output:</i> "
                             f"<code>{e(str(result['output_file']))}</code><br>")
            if result.get('summary'):
                s = str(result['summary'])[:300].replace('\n', ' ')
                parts.append(f"<i>Summary:</i> {e(s)}...")
            parts.append("</div>")

        parts.append("</body></html>")

        with open(path, 'w', encoding='utf-8') as f:
            f.write("\n".join(parts))

    # ------------------------------------------------------------ driver

    ALL_CHECKS = [
        ('dns_info',            'run_dns_info'),
        ('body_analysis',       'run_body_analysis_check'),
        ('page_analysis',       'run_page_analysis_check'),
        ('whatweb',             'run_whatweb'),
        ('ssl_nmap',            'run_nmap_ssl'),
        ('ssl_testssl',         'run_testssl'),
        ('ssl_certificate',     'run_openssl_check'),
        ('security_headers',    'run_security_headers_check'),
        ('csp_analysis',        'run_csp_analysis_check'),
        ('cache_control',       'run_cache_control_check'),
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

    def _run_one(self, name, fn):
        t0 = time.time()
        try:
            result = fn()
        except KeyboardInterrupt:
            raise
        except Exception as e:
            result = {'error': f'Unhandled exception: {e}'}
            self._log(f"[-] Error in {name}: {e}", always=True)
        elapsed = time.time() - t0
        if isinstance(result, dict):
            result['_duration_seconds'] = elapsed
        self._log(f"    ({_format_duration(elapsed)})")
        self.results[name] = result

    def run_full_audit(self):
        self.scan_start = time.time()

        self._log("=" * 70, always=True)
        self._log(f"STARTING SECURITY AUDIT FOR: {self.target_url}", always=True)
        self._log(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                  always=True)
        self._log(f"Output folder: {self.output_dir}", always=True)
        self._log(f"Mode: {'deep' if self.deep else 'standard'}", always=True)
        self._log("=" * 70, always=True)

        # Service discovery runs first and gates the rest.
        self._run_one('service_discovery', self.run_service_discovery)

        checks = self._selected_checks()
        self._log(f"\nChecks to run: {', '.join(n for n, _ in checks)}",
                  always=True)

        for name, fn in checks:
            self._run_one(name, fn)

        self.scan_end = time.time()
        total = self.scan_end - self.scan_start

        self._log("\n[*] Generating reports...")
        report = self.generate_report()

        self._log("\n" + "=" * 70, always=True)
        self._log(f"AUDIT COMPLETE in {_format_duration(total)}", always=True)
        self._log("=" * 70, always=True)
        self._log(f"Run folder  : {self.output_dir}", always=True)
        self._log(f"JSON report : {report['json_report']}", always=True)
        self._log(f"Text report : {report['summary_report']}", always=True)
        self._log(f"HTML report : {report['html_report']}", always=True)

        sev = report['report_data']['summary']['findings_by_severity']
        self._log(f"\nOpen ports: {self.open_ports}", always=True)
        self._log("Findings by severity:", always=True)
        for level in ('HIGH', 'MEDIUM', 'LOW', 'INFO'):
            self._log(f"  {level:<7}: {len(sev[level])}", always=True)
        self._log(f"Total scan time: {_format_duration(total)}", always=True)

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
        description='Web Security Audit Automation Tool (educational, v8).',
        epilog='Example: python3 audit_deepseek.py https://example.com -o results')
    parser.add_argument('target', help='Target URL or IP/host')
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
    parser.add_argument('--deep', action='store_true',
                        help='Scan a wider port range and probe more '
                             'thoroughly (slower)')
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
        deep=args.deep,
    )

    try:
        auditor.run_full_audit()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Partial results saved in", auditor.output_dir)
        sys.exit(130)


if __name__ == '__main__':
    main()
```

---

## What specifically changed vs. your v7

### 1. Scan duration everywhere
- `self.scan_start` / `self.scan_end` time the whole run.
- `_run_one()` times each check and stores `_duration_seconds` in the result.
- Console, text report, JSON, and HTML all show:
  - Total scan duration (`4m 31s`)
  - Per-check duration (`nikto (1m 12s)`)
- New "CHECK TIMINGS" section in the text report and a table in the HTML.

### 2. Comprehensive port scanning
- `COMMON_PORTS` (100+ typical ports) scanned concurrently via `_scan_ports()` using `ThreadPoolExecutor`.
- `--deep` flag swaps in `DEEP_PORTS` for a wider sweep.
- Every **open** port (not just the target's) gets probed for HTTP and HTTPS.
- Result: `open_ports` list is reported, plus a `non_http_services` list with banner grabs.

### 3. Banner grabbing
- `_banner_grab()` connects to non-HTTP open ports and reads up to 512 bytes.
- Terminal escape codes stripped.
- Included in the report so you see e.g. SSH/MySQL banners immediately.

### 4. DNS / host resolution check
- `run_dns_info()` does forward resolution, reverse DNS, and (if `dig` is installed) MX/TXT/NS/CNAME.
- Outputs a dedicated section in the HTML report.
- Works for both raw IPs and hostnames.

### 5. Nikto parsing fixed
- The old regex `^(target\s+(ip|hostname|port))` missed `Target Host:` and, due to the hashref, also didn't strip garbage.
- New skip regex covers `target ip|host|hostname|port`, `start time`, `end time`, `server:`, `no cgi directories`, `root page /`, `N host(s) tested`, `nikto v`.
- Perl `HASH(0x...)` artifacts are stripped from remaining lines.

### 6. Page-analysis deduplication
- Root page bodies are hashed; `/index.php` returning the same body as `/` is skipped.
- Avoids the duplicate "Page title" findings you saw for both `http://...:80` and `http://...:80/index.php`.

### 7. New checks
- **`csp_analysis`** — flags `'unsafe-inline'`, `'unsafe-eval'`, wildcard `*`, and missing `object-src`.
- **`cache_control`** — flags responses without `Cache-Control`, or with shared-cacheable policies.
- **Sensitive-file classification expanded** — 401/403 responses now reported as `Protected path exists`, which is often useful ("path exists, but denied").

### 8. Better evidence
- Present headers now record their actual values (`present_headers` is now a list of `{header, url, value}` objects, not just names).
- WhatWeb output parsed into per-URL findings.
- Meta tags captured.
- Script `src` values collected.

### 9. Report layout
- Text report has new sections: **CONFIRMED WEB SERVICES**, **OPEN PORTS**, **NON-HTTP SERVICES**, **CHECK TIMINGS**.
- HTML report has service and non-HTTP tables, DNS block, and per-check timings.
- JSON adds `scan_duration_seconds`, `scan_duration_human`, `open_ports`, `non_http_services`, and `check_durations`.

### 10. `--deep` flag
- Broadens the port sweep and is intended for full single-IP audits.

---

## Example usage

```bash
# Standard audit — same behaviour as v7 but with timings + port scan
python3 audit_deepseek.py 130.208.246.173

# Focused on the web service
python3 audit_deepseek.py https://example.com --skip nikto directory_discovery

# Deep scan of a single IP: broad port sweep + all checks
python3 audit_deepseek.py 192.0.2.10 --deep

# Add extra ports the org uses
python3 audit_deepseek.py 192.0.2.10 --ports 8080,8081,9000,9090
```

Once you run the updated script against `130.208.246.173`, you should see:
- A `PORT` table showing `80` open and possibly others
- A `DNS` block (with reverse DNS if available)
- Per-check timings
- A total scan duration
- Fewer false-positive "Nikto: Target Host:" entries
- No duplicate `Page title:` for `/index.php` when it matches `/`

If any output looks off (e.g., a check that's much slower than expected, or a new false positive), paste the relevant section and I'll tune the parsing.

## Prompt 7

Could you write me a script that loops over all the following ips, running the security audit on all of them?
130.208.246.171 130.208.246.173 130.208.246.176 130.208.246.177

130.208.246.180 130.208.246.168 130.208.246.166 130.208.246.170 130.208.246.164 130.208.246.175 130.208.246.174 130.208.246.167 130.208.246.165 130.208.246.185 130.208.246.213

## Response 7

# Batch Auditor — Runs the Audit Across All 15 IPs

Save this as `batch_audit.py` **in the same folder** as `audit_deepseek.py`. It imports the `WebSecurityAuditor` class directly, so no shelling out and no parsing of stdout.

```python
#!/usr/bin/env python3
"""
Batch Web Security Auditor
Runs audit_deepseek.py's WebSecurityAuditor against a list of targets.

Usage:
    python3 batch_audit.py
    python3 batch_audit.py --only security_headers cookies
    python3 batch_audit.py --skip nikto directory_discovery
    python3 batch_audit.py --deep
    python3 batch_audit.py --resume
    python3 batch_audit.py -o my_batch_results
    python3 batch_audit.py --ips 130.208.246.171 130.208.246.173

For educational use only. Only run against hosts you are authorised to test.
"""

import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime

# Import the auditor from the sibling file.
try:
    from audit_deepseek import (
        WebSecurityAuditor,
        _format_duration,
    )
except ImportError:
    print("[!] Could not import audit_deepseek.py")
    print("    Make sure batch_audit.py is in the same folder as audit_deepseek.py.")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

DEFAULT_TARGETS = [
    "130.208.246.171", "130.208.246.173", "130.208.246.176", "130.208.246.177",
    "130.208.246.180", "130.208.246.168", "130.208.246.166", "130.208.246.170",
    "130.208.246.164", "130.208.246.175", "130.208.246.174", "130.208.246.167",
    "130.208.246.165", "130.208.246.185", "130.208.246.213",
]

# Default scheme applied to bare IPs (they usually don't have TLS on 443).
DEFAULT_SCHEME = "http"


# ---------------------------------------------------------------------------
# Batch runner
# ---------------------------------------------------------------------------

class BatchAuditor:

    def __init__(self, targets, output_dir="batch_audit_results",
                 skip_checks=None, only_checks=None, quiet=False,
                 verbose=False, deep=False, resume=False, rate=50,
                 ports=None, scheme=DEFAULT_SCHEME):
        self.targets = targets
        self.output_dir = os.path.abspath(output_dir)
        self.skip_checks = skip_checks or []
        self.only_checks = only_checks or []
        self.quiet = quiet
        self.verbose = verbose
        self.deep = deep
        self.resume = resume
        self.rate = rate
        self.ports = ports
        self.scheme = scheme

        self.batch_start = None
        self.batch_end = None
        self.per_target = {}          # target -> {status, duration, report, error}

        os.makedirs(self.output_dir, exist_ok=True)

        # Load prior state if resuming.
        self.state_file = os.path.join(self.output_dir, "batch_state.json")
        if self.resume and os.path.exists(self.state_file):
            try:
                with open(self.state_file) as f:
                    prior = json.load(f)
                self.completed_targets = set(prior.get("completed_targets", []))
                print(f"[*] Resuming: {len(self.completed_targets)} target(s) "
                      f"already completed")
            except Exception as e:
                print(f"[!] Could not read prior state: {e}")
                self.completed_targets = set()
        else:
            self.completed_targets = set()

    # -------------------------------------------------------------- helpers

    def _log(self, msg, always=False):
        if always or not self.quiet:
            print(msg)

    def _normalise(self, target):
        if target.startswith(("http://", "https://")):
            return target
        return f"{self.scheme}://{target}"

    def _save_state(self):
        state = {
            "batch_started": self.batch_start,
            "targets": self.targets,
            "completed_targets": sorted(self.completed_targets),
            "per_target": {
                t: {
                    "status": v.get("status"),
                    "duration_seconds": v.get("duration_seconds"),
                    "run_dir": v.get("run_dir"),
                    "error": v.get("error"),
                    "counts": v.get("counts"),
                }
                for t, v in self.per_target.items()
            },
        }
        try:
            with open(self.state_file, "w") as f:
                json.dump(state, f, indent=2)
        except OSError as e:
            print(f"[!] Could not save batch state: {e}")

    # ------------------------------------------------------------- per-run

    def _run_one(self, target):
        url = self._normalise(target)
        self._log("\n" + "=" * 74, always=True)
        self._log(f"  TARGET {target}  ({url})", always=True)
        self._log("=" * 74, always=True)

        t0 = time.time()
        try:
            auditor = WebSecurityAuditor(
                target_url=url,
                output_dir=self.output_dir,
                skip_checks=self.skip_checks,
                only_checks=self.only_checks,
                quiet=self.quiet,
                verbose=self.verbose,
                rate=self.rate,
                ports=self.ports,
                deep=self.deep,
                flat_output=False,
            )
            report = auditor.run_full_audit()
            duration = time.time() - t0

            report_data = report.get("report_data", {})
            summary = report_data.get("summary", {})
            sev = summary.get("findings_by_severity", {})
            counts = {level: len(sev.get(level, [])) for level in
                      ("HIGH", "MEDIUM", "LOW", "INFO")}

            self.per_target[target] = {
                "status": "ok",
                "url": url,
                "duration_seconds": duration,
                "run_dir": auditor.output_dir,
                "counts": counts,
                "open_ports": report_data.get("open_ports", []),
                "services": report_data.get("services", []),
            }
            self._log(
                f"[+] {target} done in {_format_duration(duration)} — "
                f"H:{counts['HIGH']} M:{counts['MEDIUM']} "
                f"L:{counts['LOW']} I:{counts['INFO']}",
                always=True,
            )

        except KeyboardInterrupt:
            raise
        except Exception as e:
            duration = time.time() - t0
            tb = traceback.format_exc()
            self.per_target[target] = {
                "status": "error",
                "url": url,
                "duration_seconds": duration,
                "error": str(e),
            }
            self._log(f"[!] {target} failed after "
                      f"{_format_duration(duration)}: {e}", always=True)
            if self.verbose:
                self._log(tb, always=True)

        self.completed_targets.add(target)
        self._save_state()

    # -------------------------------------------------------------- driver

    def run(self):
        self.batch_start = time.time()
        print("!" * 74)
        print("WARNING: Only run this against hosts you own or have explicit")
        print("written permission to test. Unauthorized scanning is illegal.")
        print("!" * 74)

        self._log(f"\n[*] Batch audit started: "
                  f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._log(f"[*] Targets        : {len(self.targets)}")
        self._log(f"[*] Output root    : {self.output_dir}")
        self._log(f"[*] Deep mode      : {self.deep}")
        if self.resume:
            self._log(f"[*] Resume mode    : on "
                      f"({len(self.completed_targets)} already done)")

        for idx, target in enumerate(self.targets, 1):
            if self.resume and target in self.completed_targets:
                self._log(f"\n[*] ({idx}/{len(self.targets)}) Skipping "
                          f"{target} (already completed)")
                continue

            self._log(f"\n[*] ({idx}/{len(self.targets)}) Starting {target}",
                      always=True)
            self._run_one(target)

        self.batch_end = time.time()
        total = self.batch_end - self.batch_start

        # Write aggregate reports.
        self._write_batch_summary(total)

        self._log("\n" + "=" * 74, always=True)
        self._log(f"BATCH COMPLETE in {_format_duration(total)}", always=True)
        self._log("=" * 74, always=True)

        ok = [t for t, v in self.per_target.items() if v["status"] == "ok"]
        err = [t for t, v in self.per_target.items() if v["status"] == "error"]
        self._log(f"  Successful: {len(ok)}/{len(self.targets)}", always=True)
        if err:
            self._log(f"  Failed    : {len(err)}: {err}", always=True)
        self._log(f"  Batch dir : {self.output_dir}", always=True)
        self._log(f"  Summary   : "
                  f"{os.path.join(self.output_dir, 'batch_summary.txt')}",
                  always=True)
        self._log(f"  JSON      : "
                  f"{os.path.join(self.output_dir, 'batch_summary.json')}",
                  always=True)
        self._log(f"  HTML      : "
                  f"{os.path.join(self.output_dir, 'batch_summary.html')}",
                  always=True)

    # --------------------------------------------------------- summary

    def _write_batch_summary(self, total_seconds):
        # ---- JSON ----
        data = {
            "batch_started": datetime.fromtimestamp(
                self.batch_start).isoformat(timespec="seconds"),
            "batch_finished": datetime.fromtimestamp(
                self.batch_end).isoformat(timespec="seconds"),
            "batch_duration_seconds": total_seconds,
            "batch_duration_human": _format_duration(total_seconds),
            "target_count": len(self.targets),
            "per_target": self.per_target,
        }
        json_path = os.path.join(self.output_dir, "batch_summary.json")
        with open(json_path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        # ---- Text ----
        txt_path = os.path.join(self.output_dir, "batch_summary.txt")
        with open(txt_path, "w") as f:
            f.write("=" * 78 + "\n")
            f.write("BATCH SECURITY AUDIT SUMMARY\n")
            f.write(f"Started : "
                    f"{datetime.fromtimestamp(self.batch_start).strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Finished: "
                    f"{datetime.fromtimestamp(self.batch_end).strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Duration: {_format_duration(total_seconds)}\n")
            f.write(f"Targets : {len(self.targets)}\n")
            f.write("=" * 78 + "\n\n")

            # Table header
            f.write(f"{'Target':<20} {'Status':<8} {'Time':>9} "
                    f"{'High':>5} {'Med':>5} {'Low':>5} {'Info':>5}  "
                    f"Open ports\n")
            f.write("-" * 78 + "\n")

            for target in self.targets:
                entry = self.per_target.get(target)
                if not entry:
                    f.write(f"{target:<20} {'pending':<8}\n")
                    continue
                if entry["status"] == "error":
                    f.write(f"{target:<20} {'ERROR':<8} "
                            f"{_format_duration(entry['duration_seconds']):>9}  "
                            f"{entry.get('error', '')[:30]}\n")
                    continue
                c = entry["counts"]
                ports = ",".join(str(p) for p in entry.get("open_ports", []))
                f.write(
                    f"{target:<20} {'ok':<8} "
                    f"{_format_duration(entry['duration_seconds']):>9} "
                    f"{c['HIGH']:>5} {c['MEDIUM']:>5} "
                    f"{c['LOW']:>5} {c['INFO']:>5}  {ports}\n"
                )

            f.write("\n\nHOSTS WITH HIGH-SEVERITY FINDINGS\n" + "-" * 78 + "\n")
            any_high = False
            for target in self.targets:
                entry = self.per_target.get(target)
                if entry and entry["status"] == "ok" and entry["counts"]["HIGH"]:
                    any_high = True
                    f.write(f"  {target} ({entry['counts']['HIGH']} HIGH) -> "
                            f"{entry['run_dir']}\n")
            if not any_high:
                f.write("  (none)\n")

            f.write("\n\nPER-TARGET RUN DIRECTORIES\n" + "-" * 78 + "\n")
            for target in self.targets:
                entry = self.per_target.get(target)
                if entry and entry.get("run_dir"):
                    f.write(f"  {target:<20} {entry['run_dir']}\n")

        # ---- HTML ----
        html_path = os.path.join(self.output_dir, "batch_summary.html")
        self._write_batch_html(data, html_path)

    def _write_batch_html(self, data, path):
        import html as _html
        e = _html.escape
        colors = {"HIGH": "#d32f2f", "MEDIUM": "#f57c00",
                  "LOW": "#fbc02d", "INFO": "#0288d1"}

        parts = [
            "<!DOCTYPE html>",
            "<html><head><meta charset='utf-8'>",
            "<title>Batch Audit Summary</title>",
            "<style>",
            "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;",
            "max-width:1100px;margin:2em auto;padding:0 1em;color:#222;}",
            "h1{border-bottom:3px solid #333;padding-bottom:8px;}",
            "table{border-collapse:collapse;width:100%;margin-top:1em;}",
            "th,td{border:1px solid #ddd;padding:6px 10px;text-align:left;",
            "font-size:.92em;}",
            "th{background:#f4f4f4;}",
            "tr.err{background:#fdecea;}",
            ".badge{display:inline-block;padding:1px 8px;border-radius:10px;",
            "color:#fff;font-weight:600;font-size:.78em;}",
            ".ports{color:#555;font-family:monospace;font-size:.85em;}",
            "</style></head><body>",
            "<h1>Batch Security Audit Summary</h1>",
            f"<p><b>Started:</b> {e(data['batch_started'])} &middot; "
            f"<b>Finished:</b> {e(data['batch_finished'])} &middot; "
            f"<b>Duration:</b> {e(data['batch_duration_human'])} &middot; "
            f"<b>Targets:</b> {data['target_count']}</p>",
            "<table>",
            "<tr><th>Target</th><th>Status</th><th>Time</th>"
            "<th>High</th><th>Med</th><th>Low</th><th>Info</th>"
            "<th>Open ports</th><th>Report folder</th></tr>",
        ]

        for target in self.targets:
            entry = data["per_target"].get(target)
            if not entry:
                parts.append(f"<tr><td>{e(target)}</td>"
                             f"<td colspan='8'>pending</td></tr>")
                continue
            if entry["status"] == "error":
                parts.append(
                    f"<tr class='err'><td>{e(target)}</td>"
                    f"<td>ERROR</td>"
                    f"<td>{e(_format_duration(entry['duration_seconds']))}</td>"
                    f"<td colspan='5'>{e(entry.get('error','')[:120])}</td>"
                    f"<td></td></tr>"
                )
                continue

            c = entry["counts"]

            def badge(level):
                if c[level] == 0:
                    return "0"
                return (f"<span class='badge' "
                        f"style='background:{colors[level]}'>{c[level]}</span>")

            ports = ",".join(str(p) for p in entry.get("open_ports", []))
            run_dir = entry.get("run_dir", "")
            run_link = (f"<code>{e(os.path.basename(run_dir))}</code>"
                        if run_dir else "")

            parts.append(
                f"<tr><td>{e(target)}</td><td>ok</td>"
                f"<td>{e(_format_duration(entry['duration_seconds']))}</td>"
                f"<td>{badge('HIGH')}</td><td>{badge('MEDIUM')}</td>"
                f"<td>{badge('LOW')}</td><td>{badge('INFO')}</td>"
                f"<td class='ports'>{e(ports)}</td>"
                f"<td>{run_link}</td></tr>"
            )

        parts.append("</table></body></html>")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(parts))


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(
        description="Run the web security audit against a batch of targets.",
    )
    p.add_argument("--ips", nargs="*", default=None,
                   help="Override the built-in target list")
    p.add_argument("-o", "--output", default="batch_audit_results",
                   help="Output root (default: batch_audit_results)")
    p.add_argument("--scheme", default=DEFAULT_SCHEME,
                   choices=["http", "https"],
                   help="Scheme to prepend to bare IPs (default: http)")
    p.add_argument("--skip", nargs="*", default=[],
                   help="Checks to skip (passed to the auditor)")
    p.add_argument("--only", nargs="*", default=[],
                   help="Run only these checks")
    p.add_argument("--ports", default=None,
                   help="Extra ports to probe (e.g. 80,443,8080)")
    p.add_argument("--deep", action="store_true",
                   help="Wider port sweep + more thorough probes")
    p.add_argument("--resume", action="store_true",
                   help="Skip targets already recorded in batch_state.json")
    p.add_argument("--rate", type=int, default=50,
                   help="ffuf request rate (default 50)")
    p.add_argument("-q", "--quiet", action="store_true",
                   help="Suppress per-check console output")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show each external command being run")
    return p.parse_args()


def main():
    args = parse_args()

    targets = args.ips if args.ips else DEFAULT_TARGETS

    ports = [p.strip() for p in args.ports.split(",")] if args.ports else None

    batch = BatchAuditor(
        targets=targets,
        output_dir=args.output,
        skip_checks=args.skip,
        only_checks=args.only,
        quiet=args.quiet,
        verbose=args.verbose,
        deep=args.deep,
        resume=args.resume,
        rate=args.rate,
        ports=ports,
        scheme=args.scheme,
    )

    try:
        batch.run()
    except KeyboardInterrupt:
        print("\n[!] Batch interrupted by user.")
        print(f"    Partial state saved in {batch.output_dir}/batch_state.json")
        print(f"    Re-run with --resume to continue where you left off.")
        sys.exit(130)


if __name__ == "__main__":
    main()
```

---

## How It Works

### What it does
1. **Imports** `WebSecurityAuditor` directly from `audit_deepseek.py` — no shelling out, no parsing stdout.
2. **Loops** over the list of 15 IPs (default) or your `--ips` list.
3. **Prepends `http://`** by default, since these are bare IPs and typically don't serve TLS on 443. Override with `--scheme https`.
4. **Runs the full audit** on each target — it gets its own `run_TIMESTAMP_<ip>` folder inside `batch_audit_results/`.
5. **Records per-target timing and finding counts**, catches exceptions so one bad target doesn't kill the batch.
6. **Saves state** after every target, so Ctrl+C or a crash never loses progress.
7. **Writes three aggregate reports** at the end of the batch:
   - `batch_summary.txt` — human-readable table
   - `batch_summary.json` — machine-readable, per-target counts + run dir
   - `batch_summary.html` — clickable summary with severity-colored badges

### Output layout after a full run
```
batch_audit_results/
├── batch_state.json                 # resume checkpoint
├── batch_summary.txt                # ⭐ the file to start with
├── batch_summary.json
├── batch_summary.html               # ⭐ nicest to skim
├── run_20260924_130000_130.208.246.171/
│   ├── security_audit_report.json
│   ├── security_audit_summary.txt
│   ├── audit_report.html
│   └── ... raw tool outputs
├── run_20260924_130135_130.208.246.173/
│   └── ...
└── ... one folder per target
```

---

## Usage

```bash
# Make sure both files are in the same folder
ls
# audit_deepseek.py  batch_audit.py

# Full batch, defaults
python3 batch_audit.py

# Quieter run — only per-target summary lines
python3 batch_audit.py -q

# Skip slow scanners for a quick pass over all 15 IPs
python3 batch_audit.py --skip nikto directory_discovery ssl_testssl

# Only the fast header / cookie checks
python3 batch_audit.py --only security_headers cookies info_disclosure

# Deep scan of every IP
python3 batch_audit.py --deep

# Interrupted? Pick up where you left off:
python3 batch_audit.py --resume

# Test against a different list
python3 batch_audit.py --ips 10.0.0.1 10.0.0.2 10.0.0.3 --scheme https

# Custom output folder + verbose tool logging
python3 batch_audit.py -o lab5_results -v
```

---

## Key Design Choices

**Sequential, not parallel.** Running 15 audits concurrently would hammer the network and possibly trigger IDS/WAF on some of the target hosts. If you want parallelism later, wrap the loop in a `ThreadPoolExecutor` — but increase `sleep` between targets instead first.

**Bare IPs default to `http://`.** Your previous run against `130.208.246.173` showed only port 80 open and no HTTPS service, so this is the sensible default for this subnet.

**One folder per target.** The `run_TIMESTAMP_<sanitised_domain>` layout that `audit_deepseek.py` already uses means you can drop all 15 into the same batch root and nothing collides.

**Resume via state file.** `batch_state.json` records which targets have finished. `--resume` skips them. If a target errored, it's still marked completed — if you want to retry the errored ones, delete their entries from `batch_state.json` or delete the whole file.

**Error isolation.** If one IP times out or crashes the auditor, the batch logs it and moves on. `batch_summary.*` still includes it with `status: "error"` and the exception message.

**Aggregated finding counts.** `batch_summary.txt` gives you a one-glance table:

```
Target                 Status     Time    High   Med   Low  Info  Open ports
------------------------------------------------------------------------------
130.208.246.171        ok       2m 14s      0     8    10    34  80
130.208.246.173        ok       2m 31s      0     8    10    34  80
130.208.246.176        ok       3m 02s      1    12     8    41  80,8080
...
```

Then a section listing every host with HIGH findings, linking to its individual report folder.

---

## Estimated Runtime

Per your last run against `.173`, one standard scan took ~4m 30s (dominated by ffuf + dirb + nikto). For 15 IPs that's roughly **65–75 minutes** sequential. To shorten:

```bash
# Skip the three slowest checks → ~15–20 min total
python3 batch_audit.py --skip nikto directory_discovery
```

Start with that, then selectively re-run `--only nikto directory_discovery` against hosts that showed interesting services (open ports beyond 80/443, non-standard banners, etc.).

If any target behaves unexpectedly or the batch script itself misbehaves on your machine, paste the error and I'll patch it.

## Prompt 8

## Response 8
