#!/usr/bin/env python3
"""
lab_audit.py — Scoped security audit script for a LAB VM target only.

This script is intentionally NOT designed to accept arbitrary targets from
the command line. The target is set once below, in TARGET_CONFIG. Change
it to point at your lab VM before running.

Usage:
    python3 lab_audit.py

You will be asked to confirm authorization before anything runs.
"""

import shutil
import subprocess
import sys
import datetime
import os

# ============================================================
# TARGET CONFIGURATION — edit this, do not parameterize via argv
# ============================================================
TARGET_CONFIG = {
    "host": "130.208.246.173",
    "url": "http://130.208.246.173",
    "is_lab_environment": True,
    "port": 80
}

OUTPUT_DIR = "audit_results"

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

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


# Tool -> the shell command template used to invoke it.
# {host}, {url}, {port} and {wordlist} get substituted at run time.
TOOLS = {
    "whois":     {"cmd": ["whois", "{host}"], "desc": "Domain/IP ownership info"},
    "dig":       {"cmd": ["dig", "{host}", "ANY"], "desc": "DNS records"},
    "nmap":      {"cmd": ["nmap", "-sV", "-p", "{port}", "--reason", "{host}"], "desc": "Port scan + service versions"},
    "nikto":     {"cmd": ["nikto", "-h", "{url}"], "desc": "Known misconfig / vuln scan"},
    "testssl.sh":{"cmd": ["testssl.sh", "{url}"], "desc": "TLS/SSL config check"},
    "sslyze":    {"cmd": ["sslyze", "{host}"], "desc": "TLS/SSL config check (alt)"},
    "gobuster":  {"cmd": ["gobuster", "dir", "-u", "{url}", "-w", "{wordlist}"],
                  "desc": "Directory brute force (requires wordlist)"},
}


def check_tool(name: str) -> bool:
    return shutil.which(name) is not None


def confirm_authorization() -> bool:
    print("=" * 60)
    print("AUTHORIZATION CHECK")
    print("=" * 60)
    print(f"Target host: {TARGET_CONFIG['host']}")
    print(f"Target URL:  {TARGET_CONFIG['url']}")
    print()
    if not TARGET_CONFIG["is_lab_environment"]:
        print("TARGET_CONFIG['is_lab_environment'] is not True. Refusing to run.")
        print("This script is scoped to lab/authorized environments only.")
        return False

    resp = input(
        "Type EXACTLY 'I OWN OR AM AUTHORIZED TO TEST THIS TARGET' to proceed: "
    ).strip()
    if resp != "I OWN OR AM AUTHORIZED TO TEST THIS TARGET":
        print("Confirmation not received verbatim. Aborting.")
        return False
    return True


def run_tool(name: str, spec: dict, host: str, url: str, outdir: str, port: str, wordlist: str = "") -> None:
    cmd = [part.format(host=host, url=url, port=port, wordlist=wordlist) for part in spec["cmd"]]
    print(f"\n[+] Running {name}: {' '.join(cmd)}")
    outfile = os.path.join(outdir, f"{name.replace('.', '_')}.txt")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=1800
        )
        with open(outfile, "w") as f:
            f.write(f"COMMAND: {' '.join(cmd)}\n\n")
            f.write("STDOUT:\n" + result.stdout + "\n")
            f.write("STDERR:\n" + result.stderr + "\n")
        print(f"    -> saved to {outfile}")
    except subprocess.TimeoutExpired:
        print(f"    -> {name} timed out after 30 min, skipping")
    except Exception as e:
        print(f"    -> {name} failed to run: {e}")


def main():
    if not confirm_authorization():
        sys.exit(1)

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(OUTPUT_DIR, ts)
    os.makedirs(run_dir, exist_ok=True)

    host = TARGET_CONFIG["host"]
    url = TARGET_CONFIG["url"]
    port = TARGET_CONFIG["port"]

    missing = []
    available = []
    wordlist = find_wordlist()

    print("\n" + "=" * 60)
    print("TOOL AVAILABILITY CHECK")
    print("=" * 60)
    for name in TOOLS:
        if name == "gobuster" and not wordlist:
            missing.append(name)
            print(f"[MISSING] {name:12s} no wordlist found — skipping")
            continue
        if check_tool(name):
            available.append(name)
            print(f"[OK]      {name:12s} found")
        else:
            missing.append(name)
            print(f"[MISSING] {name:12s} not installed — skipping")

    if missing:
        print("\nThe following tools are not installed and were skipped:")
        for m in missing:
            print(f"  - {m}  ({TOOLS[m]['desc']})")
        print("Install them if you want full coverage (e.g. via apt/pip/gem depending on tool).")

    if not available:
        print("\nNo scanning tools available. Nothing to run.")
        sys.exit(0)

    print("\n" + "=" * 60)
    print(f"RUNNING {len(available)} AVAILABLE TOOLS AGAINST {host}")
    print("=" * 60)

    for name in available:
        run_tool(name, TOOLS[name], host, url, run_dir, port, wordlist=wordlist or "")

    # Write a summary of what ran / what didn't
    with open(os.path.join(run_dir, "_summary.txt"), "w") as f:
        f.write(f"Audit run: {ts}\n")
        f.write(f"Target: {host} / {url}\n\n")
        f.write("Tools run:\n")
        for name in available:
            f.write(f"  - {name}: {TOOLS[name]['desc']}\n")
        f.write("\nTools missing (not run):\n")
        for name in missing:
            f.write(f"  - {name}: {TOOLS[name]['desc']}\n")

    print(f"\nDone. Results in: {run_dir}/")


if __name__ == "__main__":
    main()
