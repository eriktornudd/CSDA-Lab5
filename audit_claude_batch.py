#!/usr/bin/env python3
"""
audit_claude_batch.py — Batch recon/fingerprinting audit across the CSDA-2024
Lab 5 class IP range.

This is the batch counterpart to audit_claude.py: instead of one hardcoded
target, it walks a fixed list of lab-allocated IPs (TARGET_IPS below), all of
which are confirmed, authorized lab infrastructure for this course as part of
the Lab 5 assignment (classmates mutually auditing each other's deployed
sites).

Design:
  1. Liveness sweep — a plain HTTP(S) request to port 80/443 on every host.
     Dead hosts are logged as "no site" and never touched again.
  2. Tool-by-tool phases, not host-by-host. Each scanning tool (nmap,
     whatweb, nikto, testssl.sh, gobuster) runs against EVERY live host in
     turn before the next tool starts. A given host is therefore only hit
     by one tool at a time, with a full sweep of the other hosts (and the
     inter-host delay) between repeat visits from a different tool — much
     gentler than finishing one host completely before moving to the next.
  3. Reactive port discovery — the nmap phase parses its own output for any
     other open port whose service looks like HTTP(S) (e.g. a second vhost
     on 8080, or a `php -S` dev server left running on 8000) and adds it as
     an extra endpoint. Every later phase (whatweb/nikto/testssl/gobuster)
     then runs against ALL of a host's discovered endpoints, not just
     80/443.
  4. A STATIC, rule-based pattern matcher inspects each endpoint's captured
     output and HTTP response and writes a plain-English "suggested course
     of action" file per host — leads for manual follow-up only.

This script does not exploit anything. It does not submit injection
payloads, attempt logins, brute-force credentials, or attempt privilege
escalation. All actual exploitation is manual, done by a human, after
reviewing the leads this script produces.

Usage:
    python3 audit_claude_batch.py

You will be asked ONE typed authorization confirmation for the whole batch
before anything runs.
"""

import datetime
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

# ============================================================
# TARGET CONFIGURATION
# ============================================================
# All confirmed, authorized lab servers for CSDA-2024 Lab 5. Every student
# is expected to host a site on their allocated IP; not all of them will
# have deployed one yet.
TARGET_IPS = [
    "130.208.246.171",
    "130.208.246.173",
    "130.208.246.176",
    "130.208.246.177",
    "130.208.246.180",
    "130.208.246.168",
    "130.208.246.166",
    "130.208.246.170",
    "130.208.246.164",
    "130.208.246.175",
    "130.208.246.174",
    "130.208.246.167",
    "130.208.246.165",
    "130.208.246.185",
    "130.208.246.213",
]

OUTPUT_DIR = "audit_results_batch"
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Delays to avoid tripping fail2ban / rate limiting on lab hosts and to
# avoid bursting traffic at the whole class range at once.
LIVENESS_DELAY_SECONDS = 3    # between hosts during the initial liveness sweep
HOST_DELAY_SECONDS = 15       # between hosts within a single tool's phase
ENDPOINT_DELAY_SECONDS = 5    # between multiple ports on the SAME host, same phase
PHASE_GAP_SECONDS = 5         # once, when switching from one tool's phase to the next

HTTP_PROBE_TIMEOUT = 6

# Wordlist for gobuster directory brute forcing. System-wide Linux/Kali
# locations are checked first; the copy bundled in this repo is the
# fallback for macOS and other systems that don't ship one.
WORDLIST_CANDIDATES = [
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
    "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    os.path.join(SCRIPT_DIR, "wordlists", "common.txt"),
]


def find_wordlist():
    for path in WORDLIST_CANDIDATES:
        if os.path.isfile(path):
            return path
    return None


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def build_url(ip: str, scheme: str, port: int) -> str:
    default_port = 443 if scheme == "https" else 80
    if port == default_port:
        return f"{scheme}://{ip}/"
    return f"{scheme}://{ip}:{port}/"


# ============================================================
# Authorization
# ============================================================
def confirm_authorization(ips) -> bool:
    print("=" * 70)
    print("AUTHORIZATION CHECK — BATCH LAB AUDIT")
    print("=" * 70)
    print("This will run recon/fingerprinting tools against the following")
    print(f"{len(ips)} confirmed, authorized CSDA-2024 Lab 5 lab hosts:")
    print()
    for ip in ips:
        print(f"  - {ip}")
    print()
    print("Dead hosts (nothing on port 80/443) are skipped automatically.")
    print("Live hosts are also probed for additional HTTP(S) services on")
    print("other ports (via nmap) and those get scanned too.")
    print("No exploitation, payload submission, login attempts, or brute")
    print("forcing will be performed by this script — recon/fingerprinting")
    print("only, with leads written out for manual follow-up.")
    print()

    resp = input(
        "Type EXACTLY 'I OWN OR AM AUTHORIZED TO TEST THIS TARGET' to "
        "proceed with the ENTIRE batch: "
    ).strip()
    if resp != "I OWN OR AM AUTHORIZED TO TEST THIS TARGET":
        print("Confirmation not received verbatim. Aborting.")
        return False
    return True


# ============================================================
# HTTP probing (stdlib only)
# ============================================================
def http_probe(ip: str, scheme: str, port: int, timeout: int = HTTP_PROBE_TIMEOUT) -> dict:
    url = build_url(ip, scheme, port)

    req = urllib.request.Request(
        url,
        headers={"User-Agent": "CSDA2024-Lab5-Audit/1.0 (authorized coursework recon)"},
    )

    ctx = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(200_000).decode("utf-8", errors="replace")
            return {
                "live": True,
                "url": url,
                "status": resp.status,
                "headers": dict(resp.headers),
                "body": body,
            }
    except urllib.error.HTTPError as e:
        # The server responded (with an error status) — still "live".
        try:
            body = e.read(200_000).decode("utf-8", errors="replace")
        except Exception:
            body = ""
        return {
            "live": True,
            "url": url,
            "status": e.code,
            "headers": dict(e.headers) if e.headers else {},
            "body": body,
        }
    except Exception as e:
        return {"live": False, "url": url, "error": str(e)}


def liveness_check(ip: str) -> dict:
    return {
        "http": http_probe(ip, "http", 80),
        "https": http_probe(ip, "https", 443),
    }


# nmap line looks like: "8080/tcp open  http    syn-ack Apache httpd 2.4.58"
NMAP_OPEN_SERVICE_RE = re.compile(r"^(\d+)/tcp\s+open\s+(\S+)", re.M)


def discover_web_ports(nmap_output: str) -> list:
    """Parse nmap -sV output for open ports whose service looks like HTTP(S).

    Returns a list of (port, scheme) tuples. This is what makes the script
    "reactive" — a second vhost on 8080, a `php -S` dev server on 8000, an
    alt HTTPS port, etc. all get picked up here instead of only ever
    looking at 80/443.
    """
    found = []
    for port_str, service in NMAP_OPEN_SERVICE_RE.findall(nmap_output):
        service_l = service.lower()
        if "http" not in service_l:
            continue
        scheme = "https" if ("ssl" in service_l or service_l.startswith("https")) else "http"
        found.append((int(port_str), scheme))
    return found


# ============================================================
# Tool execution
# ============================================================
def run_cli_tool(name: str, cmd: list, outdir: str, timeout: int) -> str:
    print(f"    [+] running {name}: {' '.join(cmd)}")
    outfile = os.path.join(outdir, f"{name.replace('.', '_')}.txt")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        combined = result.stdout + "\n" + result.stderr
        with open(outfile, "w") as f:
            f.write(f"COMMAND: {' '.join(cmd)}\n\n")
            f.write("STDOUT:\n" + result.stdout + "\n")
            f.write("STDERR:\n" + result.stderr + "\n")
        print(f"        -> saved to {outfile}")
        return combined
    except subprocess.TimeoutExpired:
        msg = f"{name} timed out after {timeout}s, skipping"
        print(f"        -> {msg}")
        with open(outfile, "w") as f:
            f.write(f"COMMAND: {' '.join(cmd)}\n\nTIMED OUT after {timeout}s\n")
        return ""
    except Exception as e:
        msg = f"{name} failed to run: {e}"
        print(f"        -> {msg}")
        with open(outfile, "w") as f:
            f.write(f"COMMAND: {' '.join(cmd)}\n\nFAILED TO RUN: {e}\n")
        return ""


def phase_header(title: str) -> None:
    print("\n" + "#" * 70)
    print(f"# PHASE: {title}")
    print("#" * 70)


def for_each_host_with_delay(live_ips):
    """Yields (index, ip) pairs, sleeping HOST_DELAY_SECONDS between them."""
    for i, ip in enumerate(live_ips):
        if i > 0:
            time.sleep(HOST_DELAY_SECONDS)
        yield i, ip


def sorted_endpoints(endpoints: dict):
    return sorted(endpoints.items())  # by port number


# ---- nmap phase: also the port-discovery step -------------------------
def run_nmap_phase(host_state: dict, live_ips: list) -> None:
    phase_header("nmap (service/version scan + endpoint discovery)")
    if not check_tool("nmap"):
        print("[skip] nmap not installed — skipping for all hosts (no extra-port discovery either).")
        for ip in live_ips:
            host_state[ip]["tool_skips"].setdefault("host", {})["nmap"] = "nmap not installed"
        return

    for i, ip in for_each_host_with_delay(live_ips):
        st = host_state[ip]
        print(f"\n[{i + 1}/{len(live_ips)}] {ip}")
        output = run_cli_tool(
            "nmap",
            ["nmap", "-sV", "--reason", "-Pn", "-T4", "--top-ports", "300", ip],
            st["dir"],
            timeout=600,
        )
        st["nmap_output"] = output

        for port, scheme in discover_web_ports(output):
            if port in st["endpoints"]:
                continue
            probe = http_probe(ip, scheme, port)
            probe["scheme"] = scheme
            probe["source"] = "nmap-discovered"
            if probe["live"]:
                st["endpoints"][port] = probe
                print(f"    [+] extra web service found: {scheme}://{ip}:{port}/")
            else:
                print(f"    [.] nmap suggested {scheme} on {port}, but it didn't respond to HTTP — skipping")


# ---- generic phase for a URL-based tool run against every endpoint ----
def run_url_tool_phase(
    title: str,
    tool_name: str,
    binary: str,
    build_cmd,
    timeout: int,
    host_state: dict,
    live_ips: list,
    endpoint_filter=None,
) -> None:
    phase_header(title)
    binary_ok = check_tool(binary)
    if not binary_ok:
        print(f"[skip] {binary} not installed — skipping for all hosts.")

    for i, ip in for_each_host_with_delay(live_ips):
        st = host_state[ip]
        endpoints = sorted_endpoints(st["endpoints"])
        if endpoint_filter:
            endpoints = [(p, e) for p, e in endpoints if endpoint_filter(e)]
        if not endpoints:
            continue

        print(f"\n[{i + 1}/{len(live_ips)}] {ip} ({len(endpoints)} endpoint(s))")

        for j, (port, ep) in enumerate(endpoints):
            if not binary_ok:
                st["tool_skips"].setdefault(port, {})[tool_name] = f"{binary} not installed"
                continue
            if j > 0:
                time.sleep(ENDPOINT_DELAY_SECONDS)

            url = build_url(ip, ep["scheme"], port)
            cmd = build_cmd(ip, port, ep, url)
            name = f"{tool_name}_{port}"
            output = run_cli_tool(name, cmd, st["dir"], timeout=timeout)
            st["tool_outputs"].setdefault(port, {})[tool_name] = output


def run_gobuster_phase(host_state: dict, live_ips: list, wordlist: str) -> None:
    phase_header("gobuster (directory brute force)")
    binary_ok = check_tool("gobuster")
    if not binary_ok:
        print("[skip] gobuster not installed — skipping for all hosts.")
    elif not wordlist:
        print("[skip] no wordlist file found on disk — skipping gobuster for all hosts.")

    for i, ip in for_each_host_with_delay(live_ips):
        st = host_state[ip]
        endpoints = sorted_endpoints(st["endpoints"])
        if not endpoints:
            continue

        print(f"\n[{i + 1}/{len(live_ips)}] {ip} ({len(endpoints)} endpoint(s))")

        for j, (port, ep) in enumerate(endpoints):
            if not binary_ok:
                st["tool_skips"].setdefault(port, {})["gobuster"] = "gobuster not installed"
                continue
            if not wordlist:
                st["tool_skips"].setdefault(port, {})["gobuster"] = "no wordlist file found on disk"
                continue
            if j > 0:
                time.sleep(ENDPOINT_DELAY_SECONDS)

            url = build_url(ip, ep["scheme"], port)
            cmd = ["gobuster", "dir", "-u", url, "-w", wordlist, "-q", "-t", "5", "--timeout", "10s"]
            output = run_cli_tool(f"gobuster_{port}", cmd, st["dir"], timeout=600)
            st["tool_outputs"].setdefault(port, {})["gobuster"] = output


# ============================================================
# Static, rule-based lead detection
# ============================================================
VERSIONED_HEADER_RE = re.compile(r"\d")
PASSWORD_FIELD_RE = re.compile(r"<input[^>]+type=[\"']?password", re.I)
NMAP_OPEN_PORT_RE = re.compile(r"^\d+/tcp\s+open", re.M)
NMAP_VERSIONED_RE = re.compile(r"^\d+/tcp\s+open.*\d+\.\d+", re.M)

INTERESTING_PATH_MARKERS = [
    ".git", ".env", "admin", "backup", ".bak", "config", "wp-admin",
    "phpmyadmin", ".svn", ".htaccess", "uploads", "secret", "private",
]

TLS_WEAKNESS_MARKERS = [
    "VULNERABLE", "NOT ok", "SSLv2", "SSLv3", "TLS 1.0", "TLS 1.1",
    "DROWN", "HEARTBLEED", "ROBOT", "BEAST", "POODLE", "weak",
]


def analyze_endpoint(tool_outputs: dict, probe: dict, nmap_out: str, port: int) -> list:
    """Rule-based leads for a single host:port endpoint."""
    leads = []

    headers = probe.get("headers", {}) or {}
    body = probe.get("body", "") or ""

    for header_name in ("Server", "X-Powered-By"):
        value = headers.get(header_name)
        if value and VERSIONED_HEADER_RE.search(value):
            leads.append(
                f"The '{header_name}' response header advertises a version "
                f"banner: '{value}'. Look up CVEs for this specific "
                f"version manually — do not assume it's exploitable "
                f"without checking."
            )

    if PASSWORD_FIELD_RE.search(body):
        leads.append(
            "A login form (password input field) was found here. Test it "
            "by hand (default/weak credentials, logic flaws, response "
            "differences) before reaching for automated tools like "
            "sqlmap or hydra."
        )

    nikto_out = tool_outputs.get("nikto", "")
    nikto_findings = [
        line.strip() for line in nikto_out.splitlines()
        if line.strip().startswith("+ ") and "target ip" not in line.lower()
        and "start time" not in line.lower() and "end time" not in line.lower()
    ]
    if nikto_findings:
        leads.append(
            f"nikto flagged {len(nikto_findings)} potential issue(s). "
            f"Nikto has a well-known false-positive rate — verify each "
            f"one manually before treating it as a real finding. First "
            f"few: " + " | ".join(nikto_findings[:5])
        )

    gobuster_out = tool_outputs.get("gobuster", "")
    interesting_paths = [
        line.strip() for line in gobuster_out.splitlines()
        if any(marker in line.lower() for marker in INTERESTING_PATH_MARKERS)
    ]
    if interesting_paths:
        leads.append(
            f"gobuster found {len(interesting_paths)} potentially "
            f"sensitive path(s) (matching patterns like .git/.env/admin/"
            f"backup). Go check what they actually serve by hand:\n"
            + "\n".join(f"    {p}" for p in interesting_paths[:15])
        )

    testssl_out = tool_outputs.get("testssl", "")
    weak_hits = [
        line.strip() for line in testssl_out.splitlines()
        if any(marker in line for marker in TLS_WEAKNESS_MARKERS)
    ]
    if weak_hits:
        leads.append(
            f"testssl.sh flagged {len(weak_hits)} line(s) mentioning "
            f"weak/vulnerable TLS configuration. Some testssl output is "
            f"informational only — review each line and confirm manually "
            f"before concluding it's a real weakness."
        )

    port_line_re = re.compile(rf"^{port}/tcp\s+open.*\d+\.\d+", re.M)
    versioned_services = port_line_re.findall(nmap_out)
    if versioned_services:
        leads.append(
            f"nmap identified this port's service with a version banner. "
            f"Look up CVEs for the specific version manually:\n"
            + "\n".join(f"    {s}" for s in versioned_services[:5])
        )

    whatweb_out = tool_outputs.get("whatweb", "")
    if whatweb_out.strip():
        leads.append(
            "whatweb fingerprinted this endpoint's technology stack. "
            "Cross-reference the identified CMS/framework/library "
            "versions against known CVEs manually."
        )

    if not leads:
        leads.append(
            "No obvious automated leads from this pass. Consider a manual "
            "review of this endpoint's functionality, forms, and any "
            "custom application logic — automated tools only catch known "
            "patterns."
        )

    return leads


def write_leads_file(path: str, ip: str, host_leads: list, leads_by_port: dict, skips_by_port: dict) -> None:
    with open(path, "w") as f:
        f.write(f"Suggested course of action — {ip}\n")
        f.write(f"Generated: {datetime.datetime.now().isoformat()}\n")
        f.write("=" * 70 + "\n\n")

        if host_leads:
            f.write("Host-level observations:\n")
            for i, lead in enumerate(host_leads, 1):
                f.write(f"  {i}. {lead}\n\n")

        for port in sorted(leads_by_port):
            f.write("-" * 70 + "\n")
            f.write(f"Port {port}\n")
            f.write("-" * 70 + "\n")
            for i, lead in enumerate(leads_by_port[port], 1):
                f.write(f"  {i}. {lead}\n\n")
            skips = skips_by_port.get(port)
            if skips:
                f.write("  Tools skipped on this port:\n")
                for name, reason in skips.items():
                    f.write(f"    - {name}: {reason}\n")
                f.write("\n")

        f.write("-" * 70 + "\n")
        f.write(
            "These are leads only, generated by static pattern matching. "
            "This script did NOT exploit anything, submit payloads, "
            "attempt logins, brute-force credentials, or attempt "
            "privilege escalation. Investigate and verify each lead by "
            "hand before taking any further action.\n"
        )


# ============================================================
# Main
# ============================================================
def main():
    if not confirm_authorization(TARGET_IPS):
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(OUTPUT_DIR, ts)
    os.makedirs(run_dir, exist_ok=True)

    wordlist = find_wordlist()
    if not wordlist:
        print("[!] No gobuster wordlist found on disk — gobuster will be "
              "skipped for all hosts.")

    summary = {
        "run_started": datetime.datetime.now().isoformat(),
        "targets_total": len(TARGET_IPS),
        "hosts": {},
    }

    # ---- Phase 0: liveness sweep (lightweight, one GET per host) ----
    phase_header("liveness sweep (port 80/443)")
    host_state = {}
    for i, ip in enumerate(TARGET_IPS):
        if i > 0:
            time.sleep(LIVENESS_DELAY_SECONDS)

        host_dir = os.path.join(run_dir, ip)
        os.makedirs(host_dir, exist_ok=True)

        info = liveness_check(ip)
        with open(os.path.join(host_dir, "liveness_probe.json"), "w") as f:
            json.dump(info, f, indent=2)

        endpoints = {}
        if info["http"]["live"]:
            ep = dict(info["http"])
            ep["scheme"] = "http"
            ep["source"] = "initial-probe"
            endpoints[80] = ep
        if info["https"]["live"]:
            ep = dict(info["https"])
            ep["scheme"] = "https"
            ep["source"] = "initial-probe"
            endpoints[443] = ep

        if not endpoints:
            print(f"[-] {ip}: nothing responded on port 80 or 443 — no site, skipping.")
            summary["hosts"][ip] = {"status": "no_site"}
            continue

        print(f"[+] {ip}: live (http={info['http']['live']}, https={info['https']['live']})")
        host_state[ip] = {
            "dir": host_dir,
            "endpoints": endpoints,
            "tool_outputs": {},   # port -> {tool_name: output}
            "tool_skips": {},     # port -> {tool_name: reason}
            "nmap_output": "",
        }

    live_ips = list(host_state.keys())

    if not live_ips:
        print("\nNo live hosts found in this batch. Nothing further to scan.")
    else:
        # ---- Phase 1: nmap + reactive port discovery ----
        run_nmap_phase(host_state, live_ips)
        time.sleep(PHASE_GAP_SECONDS)

        # ---- Phase 2: whatweb, against every discovered endpoint ----
        run_url_tool_phase(
            "whatweb (tech-stack fingerprinting)",
            "whatweb", "whatweb",
            lambda ip, port, ep, url: ["whatweb", url],
            timeout=120,
            host_state=host_state, live_ips=live_ips,
        )
        time.sleep(PHASE_GAP_SECONDS)

        # ---- Phase 3: nikto, against every discovered endpoint ----
        run_url_tool_phase(
            "nikto (known misconfig / vuln scan)",
            "nikto", "nikto",
            lambda ip, port, ep, url: ["nikto", "-h", url, "-timeout", "10"],
            timeout=900,
            host_state=host_state, live_ips=live_ips,
        )
        time.sleep(PHASE_GAP_SECONDS)

        # ---- Phase 4: testssl.sh, only on endpoints that are actually TLS ----
        run_url_tool_phase(
            "testssl.sh (TLS/SSL config check)",
            "testssl", "testssl.sh",
            lambda ip, port, ep, url: ["testssl.sh", "--quiet", f"{ip}:{port}"],
            timeout=600,
            host_state=host_state, live_ips=live_ips,
            endpoint_filter=lambda ep: ep.get("scheme") == "https",
        )
        time.sleep(PHASE_GAP_SECONDS)

        # ---- Phase 5: gobuster, against every discovered endpoint ----
        run_gobuster_phase(host_state, live_ips, wordlist)

        # ---- Phase 6: static analysis + per-host report ----
        phase_header("analysis (static, rule-based lead detection)")
        for ip in live_ips:
            st = host_state[ip]
            leads_by_port = {}
            skips_by_port = st["tool_skips"]

            for port, ep in sorted_endpoints(st["endpoints"]):
                leads_by_port[port] = analyze_endpoint(
                    st["tool_outputs"].get(port, {}), ep, st["nmap_output"], port
                )

            host_leads = []
            if len(st["endpoints"]) > 1:
                desc = ", ".join(
                    f"{port}/{ep['scheme']} ({ep.get('source', 'unknown')})"
                    for port, ep in sorted_endpoints(st["endpoints"])
                )
                host_leads.append(
                    f"Multiple distinct web services were found on this "
                    f"host: {desc}. Check whether these are separate apps, "
                    f"a dev/staging copy, or an old version left running — "
                    f"compare them by hand, port by port."
                )

            write_leads_file(
                os.path.join(st["dir"], "suggested_actions.txt"),
                ip, host_leads, leads_by_port, skips_by_port,
            )

            total_leads = len(host_leads) + sum(len(v) for v in leads_by_port.values())
            summary["hosts"][ip] = {
                "status": "live",
                "ports": sorted(st["endpoints"].keys()),
                "leads_count": total_leads,
            }
            print(f"[+] {ip}: {total_leads} lead(s) across {len(st['endpoints'])} "
                  f"endpoint(s) -> suggested_actions.txt")

    summary["run_finished"] = datetime.datetime.now().isoformat()
    summary["live_count"] = sum(1 for h in summary["hosts"].values() if h["status"] == "live")
    summary["no_site_count"] = sum(1 for h in summary["hosts"].values() if h["status"] == "no_site")

    summary_path = os.path.join(run_dir, "_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2)

    print("\n" + "=" * 70)
    print("BATCH COMPLETE")
    print("=" * 70)
    print(f"Live hosts:    {summary['live_count']}")
    print(f"No site:       {summary['no_site_count']}")
    print(f"Results in:    {run_dir}/")
    print(f"Summary JSON:  {summary_path}")


if __name__ == "__main__":
    main()
