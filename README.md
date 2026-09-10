# Multi-Engine File Scanner & Threat Detector

A Python-based file and directory scanner that combines several independent
detection techniques into a single unified risk score. It's designed to catch
suspicious files — from ordinary malware to ransomware-style scripts — using
a mix of local heuristics and (optionally) external AV engines.

## How it works

The scanner runs each file through up to three layers of analysis:

### 1. Local heuristic engine
No internet connection or third-party service required. For every file it:

- **Hashes** the contents (MD5, SHA1, SHA256, SHA512) for identification and
  lookup against a local known-malware hash database.
- **Measures entropy** in 4KB chunks to spot packed or encrypted payloads —
  high, uniform entropy across a file is a common sign of obfuscation or
  encryption.
- **Identifies file type** via magic-byte signatures (PE, ELF, Mach-O, ZIP,
  PDF, images, archives, etc.), independent of the file's extension.
- **Parses PE headers** for Windows executables (`.exe`, `.dll`, `.sys`, ...),
  flagging things like sections that are both writable and executable, or
  unusual virtual-to-raw size ratios that suggest packing.
- **Scans source/script content** (Python, JS, PowerShell, batch, etc.)
  against a library of behavioral patterns — ransomware notes, shadow-copy
  deletion, AMSI/ETW bypass attempts, keylogging APIs, process injection,
  credential dumping, C2/exfiltration indicators, anti-VM/anti-debug checks,
  and more — while explicitly skipping matches found in comments or inside
  the scanner's own pattern definitions (to avoid flagging itself or similar
  detection tooling as malicious).
- **Runs signature rules**, a set of regex-based detections for higher-
  confidence combinations (e.g. a reverse shell pattern, registry
  persistence keys, Discord webhook exfiltration, shellcode-like byte runs).

### 2. ClamAV integration (optional)
If a local ClamAV daemon or the `clamscan` CLI is available, the file is also
submitted to ClamAV and its verdict is folded into the overall result.

### 3. VirusTotal integration (optional)
If a `VT_API_KEY` is set, the scanner will:
- Look up the file's SHA256 hash against VirusTotal's existing database.
- Optionally upload the file itself (files ≤32 MB) for a fresh multi-engine
  scan, polling for results.

## Risk scoring

Every signal — hash-DB hits, ClamAV verdicts, VirusTotal detections, entropy,
PE characteristics, behavioral findings, and signature matches — feeds into a
weighted score from 0–100, which maps to a risk level:

| Score | Level |
|-------|-------|
| 0–4   | CLEAN |
| 5–19  | LOW |
| 20–44 | MEDIUM |
| 45–69 | HIGH |
| 70–100| CRITICAL |

A known-malware hash match short-circuits straight to `CRITICAL`.

## Usage

```bash
# Scan a single file
python scanner.py scan ./suspicious.exe

# Scan a whole directory (recursive)
python scanner.py scan ~/Downloads

# Skip VirusTotal upload, hash lookup only
python scanner.py scan ./script.py --no-vt-upload

# Heuristics-only, no ClamAV or VirusTotal
python scanner.py scan ./file --no-vt --no-clamav

# Watch a folder in real time, auto-quarantining high-risk files
python scanner.py watch ~/Downloads --quarantine

# Manage the local malware hash database
python scanner.py add-hash sha256 <hash>
python scanner.py db
```

Results print to the console with color-coded severity and are saved as a
JSON report under `reports/`. Files flagged during `watch` mode above a
score threshold can be automatically moved to a `quarantine/` folder.

## Requirements

- Python 3.10+ (uses the `:=` walrus operator)
- Optional: `requests` (VirusTotal), `watchdog` (real-time watching),
  `python-magic` (better MIME detection), `pyclamd` (ClamAV daemon socket)
- Optional: a running `clamd` daemon or `clamscan` CLI on PATH
- Optional: a VirusTotal API key exported as `VT_API_KEY`

## Disclaimer

This tool is intended for personal and educational use in scanning files you
own or have permission to analyze. It is a heuristic-based aid, not a
replacement for a dedicated, regularly-updated antivirus product — false
positives and false negatives are both possible.
