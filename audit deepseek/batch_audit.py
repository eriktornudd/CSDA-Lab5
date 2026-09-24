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