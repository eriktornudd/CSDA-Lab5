# CSDA Lab 5: AI-Assisted Security Audits of Vibecoded Websites

This project documents and automates a security audit of lab-hosted websites created during the CSDA course. It compares two approaches:

- an audit generated with Claude
- an audit generated with DeepSeek

The work combines prompt-based AI generation, scripted recon and scanning, batch execution across multiple targets, and manual follow-up testing.

## Project overview

The lab focuses on evaluating the security posture of several student-hosted web applications in a controlled academic environment. The goal is not to exploit production systems, but to:

- identify exposed services and common web vulnerabilities,
- test HTTP and TLS security controls,
- classify findings by severity,
- compare AI-generated auditing scripts and workflows,
- document the process and results in a structured report.

The primary written output is the Typst report in `Lab5.typ`, and the compiled PDF is `Lab5.pdf`.

## Repository structure

```text
CSDA-Lab5/
├── Lab5.typ                 # Main report source (Typst)
├── Lab5.pdf                 # Compiled report PDF
├── README.md                # Project overview and usage guide
├── audit claude/            # Claude-generated audit scripts and results
│   ├── Audit_claude.py      # Single-target audit script
│   ├── audit_claude_batch.py # Multi-target batch audit
│   ├── prompts_claude.md    # Interaction log / prompts and responses
│   ├── wordlists/
│   ├── audit_results/        # Timestamped single-target results
│   └── audit_results_batch/  # Batch scan outputs
├── audit deepseek/          # DeepSeek-generated audit scripts and results
│   ├── audit_deepseek.py    # Advanced multi-check auditor
│   ├── batch_audit.py       # Batch execution runner for multiple IPs
│   ├── audit_config.json    # Timing and scanner configuration
│   ├── prompts_deepseek.md  # AI prompt history
│   ├── batch_audit_results/ # Batch summaries and per-target directories
│   └── audit_results/       # Per-target scan outputs
└── .git/
```

## Lab goals

The assignment explores whether LLMs can help generate effective security-audit tooling and whether the resulting scripts produce valuable asset discovery and vulnerability leads. The project includes:

1. prompt engineering for security tooling,
2. generation of automated Python audit scripts,
3. scanning of multiple lab IPs,
4. comparison of output quality and guardrails between models,
5. manual follow-up testing based on the most suspicious findings.

## Key files

### Main report

- `Lab5.typ` — source report for the lab
- `Lab5.pdf` — rendered version of the report

### Claude audit workflow

- `audit claude/Audit_claude.py` — single-host audit script with confirmation gate
- `audit claude/audit_claude_batch.py` — course IP batch audit across multiple hosts
- `audit claude/prompts_claude.md` — prompt progression and model responses

### DeepSeek audit workflow

- `audit deepseek/audit_deepseek.py` — richer web security auditor with structured findings
- `audit deepseek/batch_audit.py` — parallel batch runner against a fixed class IP list
- `audit deepseek/audit_config.json` — scanner timeouts and configuration
- `audit deepseek/prompts_deepseek.md` — prompt progression and generated script discussion

## What the scripts do

These scripts perform ethical, authorized workflow checks on lab machines, including:

- host and port discovery,
- banner and service detection,
- TLS/SSL inspection,
- HTTP security header checks,
- cookie flag validation,
- method probing (for example OPTIONS and unsafe HTTP verbs),
- directory enumeration with wordlists,
- HTML content and endpoint review,
- report generation in text, JSON, and HTML formats.

They are designed for classroom lab targets and include authorization enforcement before running.

## Environment and requirements

The scripts depend on common security tools that may already be present on a Kali or Debian-based system. Typical commands include:

```bash
whois
nslookup
dig
nmap
nikto
testssl.sh
sslyze
gobuster
ffuf
curl
whatweb
```

In addition, Python 3 is required.

The DeepSeek script also looks for a wordlist such as:

```text
/usr/share/wordlists/dirb/common.txt
```

or a bundled fallback under the project folder.

## How to run the audits

### Single-target Claude audit

From the `audit claude` folder:

```bash
python3 Audit_claude.py
```

The script asks for a typed authorization confirmation before running. It checks for installed tools and saves output to timestamped directories under `audit_results`.

### Batch Claude audit

From the `audit claude` folder:

```bash
python3 audit_claude_batch.py
```

This script sweeps the class IP range, identifies live hosts, probes additional HTTP services, and saves findings for manual review.

### DeepSeek single-target audit

From the `audit deepseek` folder:

```bash
python3 audit_deepseek.py http://130.208.246.173
```

It can also accept custom output directories and additional flags, as described in the script docstring.

### DeepSeek batch audit

From the `audit deepseek` folder:

```bash
python3 batch_audit.py
```

This runs the auditor across the target IP list and writes summary output and per-host results into `batch_audit_results`.

## Output artifacts

The project stores large outputs under the audit directories, including:

- `_summary.txt` for high-level results,
- per-tool output files (for example `nikto.txt`, `nmap.txt`, `gobuster.txt`),
- JSON/HTML summaries,
- per-target result folders,
- batch summaries such as `batch_summary.json` and `batch_summary.txt`.

## Results summary

The report compares the output from the Claude and DeepSeek workflows and notes the following key findings:

- both models produced useful tool lists and audit scripts,
- DeepSeek was more direct and produced working scripts without the same initial refusal pattern,
- Claude required safety reassurance and confirmation gates before generating the same type of automation,
- both approaches were used to scan a range of lab IPs and identify live services,
- manual follow-up testing focused on the hosts with the strongest findings,
- no unauthorized escalation or privilege takeover was achieved during the project.

## Ethics and scope

This repository is for educational use only. All scanning and testing should be performed only on systems that are explicitly authorized for the exercise. The scripts contain confirmation prompts and are intended for lab environments rather than arbitrary public targets.

## Notes

- `Lab5.typ` is the canonical report source.
- `Lab5.pdf` is the generated deliverable.
- Output directories can be large and are intentionally retained as evidence of the audit process.

## License and usage

The project is created for academic coursework. Use it only within the approved lab scope described by the course and the assignment instructions.

## AI Disclaimer

This README.md file was generated in it's entirety by Copilot Free using the model MAI-Code-1.1-Flash.

Prompt given: `Read the entire project folder. Generate a README.md file for this project in the usual format.`
