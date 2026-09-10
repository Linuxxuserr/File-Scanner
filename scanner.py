#!/usr/bin/env python3
"""
Advanced Multi-Engine File Scanner & Threat Detector v3.1
==========================================================
Multi-engine scanning:
  1. Local heuristic engine (hash, entropy, signatures, behavioral analysis)
  2. ClamAV backend (clamd daemon or clamscan CLI)
  3. VirusTotal API (hash lookup + full file upload)
  Combined reporting from all engines with unified risk scoring.
"""

import hashlib
import math
import os
import re
import json
import shutil
import struct
import sys
import time
import logging
import argparse
import datetime
import subprocess
import socket
import importlib.util
import urllib.request
import urllib.error
from pathlib import Path
from collections import Counter
from typing import Optional

print(r"""
██╗  ██╗██████╗ ██╗      ██████╗  ██╗████████╗███████╗    ███████╗██╗██╗     ███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
╚██╗██╔╝██╔══██╗██║     ██╔═████╗███║╚══██╔══╝██╔════╝    ██╔════╝██║██║     ██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
 ╚███╔╝ ██████╔╝██║     ██║██╔██║╚██║   ██║   ███████╗    █████╗  ██║██║     █████╗      ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
 ██╔██╗ ██╔═══╝ ██║     ████╔╝██║ ██║   ██║   ╚════██║    ██╔══╝  ██║██║     ██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██╔╝ ██╗██║     ███████╗╚██████╔╝ ██║   ██║   ███████║    ██║     ██║███████╗███████╗    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝  ╚═╝╚═╝     ╚══════╝ ╚═════╝  ╚═╝   ╚═╝   ╚══════╝    ╚═╝     ╚═╝╚══════╝╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                                                                                                   """)  

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

try:
    import magic
    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False

try:
    import pyclamd
    HAS_PYCLAMD = True
except ImportError:
    HAS_PYCLAMD = False

VERSION = "3.1.0"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
QUARANTINE_DIR = os.path.join(BASE_DIR, "quarantine")
LOG_FILE = os.path.join(BASE_DIR, "scanner.log")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
KNOWN_MALWARE_DB = os.path.join(BASE_DIR, "malware_hashes.json")
VT_API_KEY = os.environ.get("VT_API_KEY", "")

# URL to fetch the canonical requirements list from for `install` command
REQUIREMENTS_URL = "https://raw.githubusercontent.com/Linuxxuserr/File-Scanner/refs/heads/main/requirements.txt"

# Maps the importable module name -> the pip package name to install
PACKAGE_MAP = {
    "requests": "requests",
    "watchdog": "watchdog",
    "magic": "python-magic",
    "pyclamd": "pyclamd",
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".drv", ".scr", ".com", ".bat", ".cmd", ".ps1",
    ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl", ".msi",
    ".pif", ".lnk", ".inf", ".reg", ".sct", ".shb", ".shs", ".gadget",
    ".jar", ".class", ".swf", ".apk", ".deb", ".rpm", ".cab", ".msu",
    ".py", ".pyw", ".rb", ".pl", ".php", ".asp", ".aspx", ".jsp", ".cgi",
    ".sh", ".bash", ".csh", ".ksh", ".so", ".dylib",
}

TEXT_EXTENSIONS = {
    ".py", ".pyw", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".sh", ".bash",
    ".php", ".asp", ".aspx", ".jsp", ".cgi", ".rb", ".pl",
    ".hta", ".reg", ".inf", ".sct", ".lnk", ".hta",
}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(LOG_FILE, mode="a"),
    ],
)
log = logging.getLogger("Scanner")


class C:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

# ──────────────────────── DEPENDENCY INSTALLER ────────────────────────

def get_missing_packages() -> list:
    """Return the pip package names for any PACKAGE_MAP entry not importable."""
    missing = []
    for import_name, pip_name in PACKAGE_MAP.items():
        if importlib.util.find_spec(import_name) is None:
            missing.append(pip_name)
    return missing


def fetch_requirements(url: str) -> Optional[list]:
    """Fetch a requirements.txt from a URL and return a list of requirement lines."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "file-scanner-installer"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode("utf-8")
        lines = [
            line.strip() for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        return lines
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.error(f"Failed to fetch requirements.txt: {e}")
        return None
    except Exception as e:
        log.error(f"Unexpected error fetching requirements.txt: {e}")
        return None


def _requirement_base_name(requirement_line: str) -> str:
    """Strip version specifiers/extras from a requirements.txt line to get the bare package name."""
    return re.split(r"[=<>!~\[;]", requirement_line)[0].strip()


def install_packages_cmd():
    """`scanner.py install` — check deps, prompt, fetch requirements.txt, install."""
    missing = get_missing_packages()

    if not missing:
        print(f"{C.GREEN}{C.BOLD}All required packages are already installed.{C.RESET}")
        return

    print(f"{C.YELLOW}{C.BOLD}The following packages are not installed:{C.RESET}")
    for pkg in missing:
        print(f"  {C.YELLOW}- {pkg}{C.RESET}")

    answer = input(f"\n{C.BOLD}Install missing packages now? (y/n): {C.RESET}").strip().lower()

    if answer not in ("y", "yes"):
        print(f"{C.RED}{C.BOLD}Cannot run: required packages are missing.{C.RESET}")
        sys.exit(1)

    print(f"{C.GREEN}{C.BOLD}Installing packages right now!{C.RESET}")

    requirements = fetch_requirements(REQUIREMENTS_URL)
    if requirements is None:
        print(f"{C.RED}Could not fetch the requirements list from:{C.RESET} {REQUIREMENTS_URL}")
        print(f"{C.RED}Aborting. Cannot run without the required packages.{C.RESET}")
        sys.exit(1)

    missing_lower = {m.lower() for m in missing}
    to_install = [
        line for line in requirements
        if _requirement_base_name(line).lower() in missing_lower
    ]

    if not to_install:
        # Fallback: nothing in the fetched file matched what's missing locally,
        # just install the missing package names directly.
        to_install = missing

    for requirement in to_install:
        print(f"{C.CYAN}Installing package: {requirement}{C.RESET}")
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", requirement],
                stdout=subprocess.DEVNULL if False else None,
            )
        except subprocess.CalledProcessError as e:
            print(f"{C.RED}{C.BOLD}Failed to install {requirement}: {e}{C.RESET}")
            print(f"{C.RED}Cannot run: required packages are missing.{C.RESET}")
            sys.exit(1)

    still_missing = get_missing_packages()
    if still_missing:
        print(f"{C.YELLOW}Installed, but still missing (may need a manual install): "
              f"{', '.join(still_missing)}{C.RESET}")
    else:
        print(f"{C.GREEN}{C.BOLD}All packages installed successfully!{C.RESET}")


def ensure_dependencies_or_exit():
    """Used by other commands (scan/watch) to fail fast with a clear message
    if required packages are missing, instead of silently degrading."""
    missing = get_missing_packages()
    if missing:
        print(f"{C.YELLOW}Note: optional packages not installed: {', '.join(missing)}{C.RESET}")
        print(f"{C.YELLOW}Run '{os.path.basename(sys.argv[0])} install' to add them.{C.RESET}\n")

# ──────────────────────── MALWARE HASH DB ────────────────────────

def load_malware_db() -> dict:
    db = {"md5": set(), "sha1": set(), "sha256": set()}
    if os.path.exists(KNOWN_MALWARE_DB):
        try:
            with open(KNOWN_MALWARE_DB) as f:
                data = json.load(f)
            for algo in db:
                for h in data.get(algo, []):
                    db[algo].add(h.lower())
            log.info(f"Malware DB loaded: {sum(len(v) for v in db.values())} hashes")
        except Exception as e:
            log.warning(f"Failed to load malware DB: {e}")
    return db

def save_malware_db(db: dict):
    with open(KNOWN_MALWARE_DB, "w") as f:
        json.dump({k: list(v) for k, v in db.items()}, f, indent=2)

# ──────────────────────── HASHING ────────────────────────

def compute_hashes(filepath: str) -> dict:
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(),
         "sha256": hashlib.sha256(), "sha512": hashlib.sha512()}
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            for v in h.values():
                v.update(chunk)
    return {k: v.hexdigest() for k, v in h.items()}

# ──────────────────────── ENTROPY ────────────────────────

def compute_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())

def compute_entropy_analysis(filepath: str) -> dict:
    entropies = []
    with open(filepath, "rb") as f:
        while chunk := f.read(4096):
            entropies.append(compute_entropy(chunk))
    if not entropies:
        return {"overall": 0.0, "max": 0.0, "avg": 0.0, "high_chunks": 0, "total_chunks": 0}

    all_data = open(filepath, "rb").read()
    high = sum(1 for e in entropies if e > 7.0)
    very_high = sum(1 for e in entropies if e > 7.5)
    return {
        "overall": compute_entropy(all_data),
        "max": max(entropies),
        "min": min(entropies),
        "avg": sum(entropies) / len(entropies),
        "high_chunks": high,
        "very_high_chunks": very_high,
        "total_chunks": len(entropies),
        "high_ratio": high / len(entropies) if entropies else 0,
    }

# ──────────────────────── MAGIC / MIME ────────────────────────

MAGIC_BYTES = {
    b"MZ": "PE executable",
    b"\x7fELF": "ELF executable",
    b"PK": "ZIP / OOXML",
    b"\xca\xfe\xba\xbe": "Mach-O / Java Class",
    b"\xfe\xed\xfa\xce": "Mach-O 32-bit",
    b"\xfe\xed\xfa\xcf": "Mach-O 64-bit",
    b"\x1f\x8b": "GZIP archive",
    b"Rar!": "RAR archive",
    b"7z\xbc\xaf\x27\x1c": "7-Zip archive",
    b"%PDF": "PDF document",
    b"\xd0\xcf\x11\xe0": "OLE / Office legacy",
    b"\xff\xd8\xff": "JPEG image",
    b"\x89PNG": "PNG image",
    b"GIF8": "GIF image",
    b"RIFF": "RIFF container",
    b"BM": "BMP image",
}

def detect_magic(data: bytes) -> str:
    for magic_bytes, desc in MAGIC_BYTES.items():
        if data[:len(magic_bytes)] == magic_bytes:
            return desc
    return "Unknown"

def detect_mime(filepath: str) -> str:
    if HAS_MAGIC:
        try:
            return magic.Magic(mime=True).from_file(filepath)
        except Exception:
            pass
    ext_map = {
        ".exe": "application/x-dosexec", ".dll": "application/x-dosexec",
        ".pdf": "application/pdf", ".zip": "application/zip",
        ".py": "text/x-python", ".js": "application/javascript",
        ".sh": "application/x-shellscript", ".so": "application/x-sharedlib",
    }
    _, ext = os.path.splitext(filepath)
    return ext_map.get(ext.lower(), "application/octet-stream")

# ──────────────────────── PE ANALYSIS ────────────────────────

class PEAnalyzer:
    @staticmethod
    def is_pe(filepath: str) -> bool:
        try:
            with open(filepath, "rb") as f:
                if f.read(2) != b"MZ":
                    return False
                f.seek(0x3C)
                f.seek(struct.unpack("<I", f.read(4))[0])
                return f.read(4) == b"PE\x00\x00"
        except Exception:
            return False

    @staticmethod
    def parse_pe(filepath: str) -> dict:
        info = {"is_64bit": False, "sections": [], "suspicious_imports": []}
        try:
            with open(filepath, "rb") as f:
                f.seek(0x3C)
                pe_off = struct.unpack("<I", f.read(4))[0]
                f.seek(pe_off + 4)
                info["is_64bit"] = struct.unpack("<H", f.read(2))[0] == 0x8664
                f.seek(pe_off + 24)
                opt_size = struct.unpack("<H", f.read(2))[0]
                num_sec = struct.unpack("<H", f.read(2))[0]
                f.seek(pe_off + 24 + opt_size)
                for _ in range(min(num_sec, 30)):
                    sec = f.read(40)
                    if len(sec) < 40:
                        break
                    chars = struct.unpack("<I", sec[36:40])[0]
                    info["sections"].append({
                        "name": sec[:8].rstrip(b"\x00").decode("ascii", errors="replace"),
                        "virtual_size": struct.unpack("<I", sec[8:12])[0],
                        "raw_size": struct.unpack("<I", sec[16:20])[0],
                        "executable": bool(chars & 0x20000000),
                        "writable": bool(chars & 0x80000000),
                    })
        except Exception as e:
            info["error"] = str(e)
        return info

# ──────────────────────── TEXT-BASED ANALYSIS ────────────────────────

DANGEROUS_IMPORTS_PY = [
    "os.system", "subprocess", "ctypes", "ctypes.windll", "ctypes.CDLL",
    "shutil.rmtree", "os.remove", "os.unlink", "os.rename",
    "crypto", "cipher", "AES", "Fernet", "encrypt", "decrypt",
    "base64.b64decode", "codecs.decode", "exec(", "eval(",
    "compile(", "__import__",
    "socket.socket", "socket.connect", "socket.bind", "socket.listen",
    "urllib.request", "requests.post", "requests.get",
    "paramiko", "ftplib", "smtplib",
    "winreg", "win32api", "win32com",
    "keyboard", "pynput", "pyautogui",
    "psutil", "threading.Thread", "multiprocessing",
    "webbrowser.open", "subprocess.Popen",
]

DANGEROUS_IMPORTS_JS = [
    "child_process", "fs.writeFileSync", "fs.unlinkSync",
    "require('child_process')", "require('fs')",
    "process.env", "process.exit",
    "execSync", "spawnSync", "exec(",
    "ActiveXObject", "WScript.Shell",
    "XMLHttpRequest", "fetch(",
    "navigator", "window.location",
]

DANGEROUS_IMPORTS_PS = [
    "Invoke-Expression", "IEX", "Invoke-WebRequest",
    "DownloadString", "DownloadFile",
    "Start-Process", "New-Object Net.WebClient",
    "[System.Reflection.Assembly]::Load",
    "Add-Type", "DllImport",
    "Set-MpPreference", "DisableRealtimeMonitoring",
    "Get-WmiObject", "Get-Process",
    "Invoke-Mimikatz", "Invoke-CredentialInjection",
    "EncodedCommand", "-enc ", "-e ",
    "Bypass", "-ExecutionPolicy Bypass",
]

DANGEROUS_IMPORTS_BAT = [
    "del /f /q", "rd /s /q", "format ",
    "cipher /w:", "vssadmin delete shadows",
    "wmic shadowcopy delete",
    "bcdedit /set {default} recoveryenabled no",
    "reg add", "schtasks /create",
    "net user", "net localgroup administrators",
    "taskkill /f", "shutdown /s",
    "powershell -enc", "powershell -e ",
    "curl ", "wget ", "certutil -urlcache",
    "bitsadmin /transfer",
]

MALICIOUS_BEHAVIOR_PATTERNS = [
    (r"(?i)(?:your|all|the|my)\s+(?:files?|data|documents?|photos?)\s+(?:have been|has been|are|is)\s+encrypt", "Ransomware encryption notice"),
    (r"(?i)decrypt(?:ion)?\s+(?:key|tool|software|service)", "Ransomware decryption demand"),
    (r"(?i)pay\s+(?:a\s+)?ransom|bitcoin\s+(?:wallet|address|payment)|monero|wire.transfer", "Ransom payment demand"),
    (r"(?i)(?:files?\s+will\s+be|data\s+will\s+be|everything\s+will\s+be)\s+(?:deleted|destroyed|lost|gone)", "Destruction threat"),
    (r"(?i)(?:time\s+remaining|countdown|hours?\s+remaining|days?\s+remaining)", "Ransom countdown timer"),
    (r"(?i)(?:enter\s+(?:the\s+)?(?:decryption|unlock|encryption)\s+key|correct\s+key)", "Ransom key input"),
    (r"(?i)(?:subprocess\.call|subprocess\.Popen|subprocess\.run|os\.system)\s*\(", "External process execution"),
    (r"(?i)(?:shutil\.rmtree|os\.remove|os\.unlink|os\.system\s*\(\s*['\"]rm)", "File system destruction"),
    (r"(?i)(?:keyboard\.block_key|keyboard\.unhook|block_key|unhook_all)", "Keyboard blocking/hooking"),
    (r"(?i)(?:encrypt\s*\(|\.encrypt\(|AES\.|Fernet|cipher\.|Crypto\.|pycryptodome)", "Encryption operations"),
    (r"(?i)(?:os\.walk|glob\.glob|os\.listdir|pathlib|Path\s*\()", "File enumeration"),
    (r"(?i)(?:fullscreen|topmost|overrideredirect|wm_delete_window)", "Full-screen UI lock"),
    (r"(?i)(?:discord\.com/api/webhooks|webhook|exfil|send.*(?:info|data|screenshot))", "Data exfiltration"),
    (r"(?i)(?:get_pc_info|gethostname|getuser|get_adapters_info|public.ip|local.ip)", "System fingerprinting"),
    (r"(?i)(?:socket\.SOCK_DGRAM|socket\.connect|socket\.bind|reverse.?shell)", "Network socket operations"),
    (r"(?i)(?:base64\.b64encode|requests\.post.*base64|b64encode)", "Base64 data encoding/exfil"),
    (r"(?i)(?:screenshot|capture|ImageGrab|pyautogui\.screenshot)", "Screenshot capture"),
    (r"(?i)(?:watchdog|restart|re-launch|reopen|persistence|survive|kill)", "Persistence/watchdog mechanism"),
    (r"(?i)(?:system32|\\\\windows\\\\|C:\\\\Users|\\\\Documents\\\\|\\\\Desktop\\\\)", "Windows system path access"),
    (r"(?i)(?:DisableRealtimeMonitoring|Set-MpPreference|Add-MpPreference|exclusion)", "AV evasion/disabling"),
    (r"(?i)(?:vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog|bcdedit)", "Shadow copy/catalog deletion"),
    (r"(?i)(?:shutdown|logoff|restart.*\/[rf]|\/s\s+\/f\s+\/t)", "System shutdown/restart"),
    (r"(?i)(?:net\s+user.*\/add|net\s+localgroup.*admin|schtasks|at\s+\d)", "User/scheduled task creation"),
    (r"(?i)(?:curl\s+.*-o|wget\s+.*-O|Invoke-WebRequest.*-OutFile|DownloadFile)", "Remote file download"),
    (r"(?i)(?:certutil\s+-urlcache|bitsadmin\s+/transfer|start-bitstransfer)", "LOLBin download"),
    (r"(?i)(?:\\\\[a-z0-9]+\\[a-z0-9\$]+|\\\\[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", "Network share/IP access"),
    (r"(?i)(?:GetAsyncKeyState|SetWindowsHookEx|GetKeyState|keylog|GetKeyboardState)", "Keylogging"),
    (r"(?i)(?:mimikatz|sekurlsa|lsadump|bloodhound|cobalt.strike|metasploit|msfvenom)", "Offensive security tooling"),
    (r"(?i)(?:VirtualAlloc|VirtualProtect|WriteProcessMemory|CreateRemoteThread|NtMapViewOfSection)", "Process injection"),
    (r"(?i)(?:AmsiUtils|amsiInitFailed|AmsiScanBuffer|AmsiOpenSession|ETW.*patch)", "AMSI/ETW bypass"),
    (r"(?i)(?:IsDebuggerPresent|CheckRemoteDebugger|NtQueryInformationProcess|anti.?debug)", "Anti-debugging"),
    (r"(?i)(?:VMware|VBox|VirtualBox|QEMU|SbieDll|Sandboxie|Cuckoo|wine_get_unix_file_name)", "Anti-VM/sandbox"),
    (r"(?i)(?:tor2web|\.onion|tor.*proxy|socks5|SOCKS)", "Tor/anonymization"),
    (r"(?i)(?:ransom|hostage)", "Ransomware language"),
    (r"(?i)(?:your\s+(?:files?|data|documents?|photos?|everything)\s+(?:has|have|are)\s+encrypt)", "Ransomware language"),
    (r"(?i)(?:pay.*bitcoin|bitcoin.*address.*send)", "Ransomware language"),
    (r"(?i)(?:FSociety|WannaCry|Petya|NotPetya|Locky|Cerber|Dharma|Phobos)", "Known ransomware family references"),
]

MAGIC_BYTES_SUSPICIOUS = {
    b"MZ": 8,
    b"\x7fELF": 8,
    b"PK": 3,
    b"\xca\xfe\xba\xbe": 7,
    b"\xfe\xed\xfa\xce": 7,
    b"\xfe\xed\xfa\xcf": 7,
    b"\xd0\xcf\x11\xe0": 6,
}


class ScanResult:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.file_size = 0
        self.hashes = {}
        self.magic = ""
        self.mime = ""
        self.entropy = {}
        self.pe_info = {}
        self.text_findings = []
        self.signature_matches = []
        self.hash_db_match = False
        self.clamav_result = None
        self.vt_hash_result = None
        self.vt_upload_result = None
        self.risk_score = 0
        self.risk_level = "CLEAN"
        self.scan_time = 0
        self.errors = []
        self.is_text_file = False
        self.scan_engines = []

    def to_dict(self) -> dict:
        return {
            "file": self.filepath,
            "filename": self.filename,
            "size_bytes": self.file_size,
            "hashes": self.hashes,
            "magic": self.magic,
            "mime": self.mime,
            "entropy": self.entropy,
            "pe_info": self.pe_info,
            "is_text_file": self.is_text_file,
            "text_findings_count": len(self.text_findings),
            "text_findings": self.text_findings[:100],
            "signature_matches": self.signature_matches,
            "hash_db_match": self.hash_db_match,
            "clamav": self.clamav_result,
            "virustotal_hash": self.vt_hash_result,
            "virustotal_upload": self.vt_upload_result,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "scan_engines": self.scan_engines,
            "scan_time_seconds": round(self.scan_time, 3),
            "errors": self.errors,
        }


def calculate_risk_score(result: ScanResult) -> tuple:
    score = 0

    if result.hash_db_match:
        return 100, "CRITICAL"

    clam = result.clamav_result
    if clam:
        if clam.get("infected"):
            score += 60
        elif clam.get("error"):
            pass

    vt = result.vt_hash_result
    if vt and "malicious" in vt:
        mal = vt["malicious"]
        total = vt.get("total_engines", 70)
        if mal > 0:
            ratio = mal / max(total, 1)
            if mal >= 20 or ratio > 0.4:
                score += 60
            elif mal >= 10 or ratio > 0.2:
                score += 45
            elif mal >= 5:
                score += 35
            elif mal >= 2:
                score += 25
            elif mal >= 1:
                score += 15
        sus = vt.get("suspicious", 0)
        if sus > 5:
            score += 15
        elif sus > 0:
            score += 8

    vt_up = result.vt_upload_result
    if vt_up and "malicious" in vt_up:
        mal = vt_up["malicious"]
        total = vt_up.get("total_engines", 70)
        if mal > 0:
            ratio = mal / max(total, 1)
            if mal >= 20 or ratio > 0.4:
                score += 60
            elif mal >= 10 or ratio > 0.2:
                score += 45
            elif mal >= 5:
                score += 35
            elif mal >= 2:
                score += 25
            elif mal >= 1:
                score += 15
        sus = vt_up.get("suspicious", 0)
        if sus > 5:
            score += 15
        elif sus > 0:
            score += 8

    ent = result.entropy.get("overall", 0)
    if ent > 7.8:
        score += 18
    elif ent > 7.3:
        score += 12
    elif ent > 6.8:
        score += 6

    high_ratio = result.entropy.get("high_ratio", 0)
    if high_ratio > 0.5:
        score += 12
    elif high_ratio > 0.3:
        score += 6

    very_high = result.entropy.get("very_high_chunks", 0)
    if very_high > 50:
        score += 8
    elif very_high > 10:
        score += 4

    if result.pe_info:
        secs = result.pe_info.get("sections", [])
        exec_writable = sum(1 for s in secs if s.get("executable") and s.get("writable"))
        if exec_writable >= 3:
            score += 15
        elif exec_writable >= 1:
            score += 8

        for s in secs:
            if s.get("raw_size", 0) > 0:
                ratio = s.get("virtual_size", 0) / s["raw_size"]
                if ratio > 10:
                    score += 10
                    break

    if result.magic in MAGIC_BYTES_SUSPICIOUS:
        score += MAGIC_BYTES_SUSPICIOUS[result.magic]

    dangerous_mimes = {"application/x-dosexec", "application/x-msdownload",
                       "application/x-executable", "application/x-sharedlib",
                       "application/java-archive", "application/x-python-bytecode"}
    if result.mime in dangerous_mimes:
        score += 8

    text_hits = result.text_findings
    if text_hits:
        critical_count = sum(1 for f in text_hits if f.get("severity") == "CRITICAL")
        high_count = sum(1 for f in text_hits if f.get("severity") == "HIGH")
        medium_count = sum(1 for f in text_hits if f.get("severity") == "MEDIUM")
        low_count = sum(1 for f in text_hits if f.get("severity") == "LOW")
        total = len(text_hits)

        score += critical_count * 22
        score += high_count * 12
        score += medium_count * 6
        score += low_count * 2

        if total >= 15:
            score += 50
        elif total >= 10:
            score += 40
        elif total >= 7:
            score += 30
        elif total >= 5:
            score += 20
        elif total >= 3:
            score += 12
        elif total >= 1:
            score += 5

        categories_found = set(f.get("category", "") for f in text_hits)
        num_categories = len(categories_found)
        if num_categories >= 6:
            score += 30
        elif num_categories >= 5:
            score += 25
        elif num_categories >= 4:
            score += 20
        elif num_categories >= 3:
            score += 15
        elif num_categories >= 2:
            score += 8

        combos = [
            ({"ransomware", "persistence", "exfiltration"}, 25),
            ({"ransomware", "encryption", "file_access"}, 20),
            ({"persistence", "evasion", "process_execution"}, 15),
            ({"exfiltration", "reconnaissance"}, 10),
            ({"ransomware", "destruction"}, 20),
            ({"encryption", "file_access", "exfiltration"}, 15),
        ]
        for combo_set, bonus in combos:
            if combo_set.issubset(categories_found):
                score += bonus

    sig_critical = 0
    sig_high = 0
    for sig in result.signature_matches:
        sev = sig.get("severity", "LOW")
        if sev == "CRITICAL":
            score += 18
            sig_critical += 1
        elif sev == "HIGH":
            score += 10
            sig_high += 1
        elif sev == "MEDIUM":
            score += 5
        elif sev == "LOW":
            score += 2

    sig_total = len(result.signature_matches)
    if sig_total >= 5:
        score += 25
    elif sig_total >= 3:
        score += 15
    elif sig_total >= 1:
        score += 5

    if sig_critical >= 3:
        score += 20
    elif sig_critical >= 2:
        score += 12
    if sig_high >= 3:
        score += 10

    score = min(score, 100)

    if score >= 70:
        level = "CRITICAL"
    elif score >= 45:
        level = "HIGH"
    elif score >= 20:
        level = "MEDIUM"
    elif score >= 5:
        level = "LOW"
    else:
        level = "CLEAN"

    return score, level


def _is_comment_or_pattern_line(line: str) -> bool:
    stripped = line.strip()

    if stripped.startswith("#"):
        return True
    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
        return True
    if stripped.upper().startswith("REM ") or stripped.upper().startswith("::"):
        return True
    if re.match(r'''^\s*\(\s*r["']''', stripped):
        return True
    if re.match(r'''^\s*["']\s*r["']''', stripped):
        return True
    if re.match(r'''^\s*(?:rule|signature|pattern|match)\s+\w+''', stripped, re.IGNORECASE):
        return True
    if re.match(r'''^\s*["']?(?:name|rule|severity|pattern|description|category)\s*["']?\s*[:=]''', stripped, re.IGNORECASE):
        return True
    if re.match(r'''\s*\{\s*["'](?:name|rule)["']\s*:''', stripped):
        return True
    if re.match(r'''^\s*["'][A-Z][a-z].*(?:ransomware|ransom|encrypt|exfil|hook|bypass|evasion|watchdog|persistence|enumeration|fingerprint|destruction|injection|keylog|download|shutdown|creation|capture|socket|encoding|lock|timer|demand|threat|bypass|monitor|attack|access|tool|language|references|mechanism|operations|cancellation|operations|interception|detection|disabling|evasion|tooling|deletion|deletion|download|access|logging|dumping|locking|hijack|targeting|bypass)\b''', stripped):
        return True

    return False


def _is_scanner_or_security_tool(filepath: str) -> bool:
    try:
        with open(filepath, "r", errors="replace") as f:
            head = f.read(32768)
    except Exception:
        return False

    scanner_indicators = [
        r"(?:class\s+\w*Scanner|def\s+scan_file|def\s+calculate_risk)",
        r"(?:MALICIOUS_BEHAVIOR_PATTERNS|SIGNATURE_RULES|YARA_LIKE_RULES)",
        r"(?:def\s+signature_scan|def\s+text_based_analysis|def\s+compute_entropy)",
        r"(?:risk_score|risk_level|ScanResult|threat_detect|quarantine)",
        r"(?:class\s+\w*(?:Engine|Detector|Analyzer|Heuristic|Result))",
        r"(?:BASE_DIR|QUARANTINE_DIR|REPORT_DIR|KNOWN_MALWARE_DB|VT_API_KEY)",
        r"(?:clamav|ClamAV|clamscan|pyclamd|virustotal)",
        r"(?:def\s+quarantine_file|def\s+print_result|def\s+save_report)",
        r"(?:def\s+load_malware_db|def\s+save_malware_db)",
        r"(?:hashtools|hashlib|compute_hashes|HashComputer)",
    ]

    hits = 0
    for pat in scanner_indicators:
        if re.search(pat, head):
            hits += 1

    return hits >= 4


def text_based_analysis(filepath: str, raw_content: bytes = None) -> list:
    findings = []
    try:
        if raw_content is None:
            raw_content = open(filepath, "rb").read()

        if len(raw_content) == 0:
            return findings

        content = None
        for enc in ("utf-8", "latin-1", "ascii", "utf-16-le", "cp1252"):
            try:
                content = raw_content.decode(enc)
                break
            except (UnicodeDecodeError, LookupError):
                continue

        if content is None:
            return findings

        if _is_scanner_or_security_tool(filepath):
            return findings

        lines = content.split("\n")

        for pattern_str, description in MALICIOUS_BEHAVIOR_PATTERNS:
            try:
                matches_in_file = list(re.finditer(pattern_str, content, re.IGNORECASE | re.DOTALL))
            except re.error:
                continue

            if not matches_in_file:
                continue

            for m in matches_in_file[:3]:
                line_num = content[:m.start()].count("\n") + 1
                match_line = lines[line_num - 1] if line_num <= len(lines) else ""

                if _is_comment_or_pattern_line(match_line):
                    continue

                start = max(0, m.start() - 40)
                end = min(len(content), m.end() + 40)
                context = content[start:end].replace("\n", " ").strip()

                if re.search(r'''r["'][\^$(]|\\x[0-9a-f]{2}\\x|\(\?i\)|\["'\]severity''', context):
                    continue

                severity = "MEDIUM"
                cat = "generic"

                desc_lower = description.lower()
                if "ransomware" in desc_lower or "ransom" in desc_lower:
                    severity = "CRITICAL"
                    cat = "ransomware"
                elif "destruction" in desc_lower or "delete" in desc_lower or "destroy" in desc_lower:
                    severity = "CRITICAL"
                    cat = "destruction"
                elif "injection" in desc_lower or "anti-debug" in desc_lower or "bypass" in desc_lower:
                    severity = "HIGH"
                    cat = "evasion"
                elif "exfiltration" in desc_lower or "webhook" in desc_lower or "screenshot" in desc_lower:
                    severity = "HIGH"
                    cat = "exfiltration"
                elif "persistence" in desc_lower or "watchdog" in desc_lower or "restart" in desc_lower:
                    severity = "HIGH"
                    cat = "persistence"
                elif "keylog" in desc_lower or "hook" in desc_lower:
                    severity = "HIGH"
                    cat = "surveillance"
                elif "process" in desc_lower or "execute" in desc_lower or "shell" in desc_lower:
                    severity = "HIGH"
                    cat = "process_execution"
                elif "encryption" in desc_lower:
                    severity = "HIGH"
                    cat = "encryption"
                elif "file" in desc_lower and ("access" in desc_lower or "enumeration" in desc_lower or "destruction" in desc_lower):
                    severity = "MEDIUM"
                    cat = "file_access"
                elif "network" in desc_lower or "socket" in desc_lower or "download" in desc_lower:
                    severity = "MEDIUM"
                    cat = "network"
                elif "reconnaissance" in desc_lower or "fingerprint" in desc_lower:
                    severity = "MEDIUM"
                    cat = "reconnaissance"
                elif "shutdown" in desc_lower or "user" in desc_lower or "scheduled" in desc_lower:
                    severity = "MEDIUM"
                    cat = "system_modification"
                elif "av evasion" in desc_lower or "disabling" in desc_lower:
                    severity = "HIGH"
                    cat = "evasion"
                elif "offensive" in desc_lower:
                    severity = "HIGH"
                    cat = "offensive_tool"

                findings.append({
                    "description": description,
                    "severity": severity,
                    "category": cat,
                    "line": line_num,
                    "context": context[:200],
                })

        ext = os.path.splitext(filepath)[1].lower()
        if ext == ".py":
            imports_to_check = DANGEROUS_IMPORTS_PY
        elif ext in (".js", ".jse", ".wsh", ".wsf"):
            imports_to_check = DANGEROUS_IMPORTS_JS
        elif ext in (".ps1", ".psm1", ".psd1"):
            imports_to_check = DANGEROUS_IMPORTS_PS
        elif ext in (".bat", ".cmd"):
            imports_to_check = DANGEROUS_IMPORTS_BAT
        else:
            imports_to_check = DANGEROUS_IMPORTS_PY + DANGEROUS_IMPORTS_JS + DANGEROUS_IMPORTS_PS + DANGEROUS_IMPORTS_BAT

        found_imports = []
        for imp in imports_to_check:
            if imp.lower() in content.lower():
                found_imports.append(imp)

        if found_imports:
            severity = "LOW"
            if len(found_imports) >= 10:
                severity = "HIGH"
            elif len(found_imports) >= 5:
                severity = "MEDIUM"

            findings.append({
                "description": f"Dangerous imports/commands detected ({len(found_imports)})",
                "severity": severity,
                "category": "imports",
                "context": ", ".join(found_imports[:20]),
                "line": 0,
            })

        malware_naming = re.findall(
            r"(?i)(?:class|def|function|var|let|const)\s+(ransomware|ransom|encryptor|decryptor|"
            r"crypto_lock|file_locker|wiper|destroyer|stealer|grabber|keylogger|"
            r"backdoor|trojan|rat|botnet|c2|beacon|payload|dropper|loader|"
            r"extractor|harvester|scanner_|worm)",
            content
        )
        if malware_naming:
            findings.append({
                "description": f"Malware-indicative identifiers: {', '.join(set(m[0] for m in malware_naming))}",
                "severity": "HIGH",
                "category": "naming",
                "context": ", ".join(set(m[0] for m in malware_naming)),
                "line": 0,
            })

        user_dir_targets = re.findall(
            r"(?:Documents|Desktop|Pictures|Downloads|Videos|Music|OneDrive|Dropbox)",
            content
        )
        if len(user_dir_targets) >= 3:
            findings.append({
                "description": f"Multiple user data directories referenced ({len(user_dir_targets)} times)",
                "severity": "MEDIUM",
                "category": "file_access",
                "context": ", ".join(set(user_dir_targets)),
                "line": 0,
            })

    except Exception as e:
        log.error(f"Text analysis error: {e}")

    return findings


SIGNATURE_RULES = [
    {"name": "PowerShell_Obfuscation", "pattern": rb"(?:powershell|pwsh).*(?:-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,})", "severity": "HIGH"},
    {"name": "Base64_Executable_Loader", "pattern": rb"(?:base64|b64decode|atob)\s*[\(\"']*[A-Za-z0-9+/=]{100,}", "severity": "HIGH"},
    {"name": "Reverse_Shell", "pattern": rb"(?:socket\.connect|\.connect\().*(?:subprocess|os\.popen|exec\(|eval\()", "severity": "CRITICAL"},
    {"name": "Registry_Persistence", "pattern": rb"(?:CurrentVersion\\\\Run|CurrentVersion\\\\RunOnce|Winlogon\\\\Shell)", "severity": "HIGH"},
    {"name": "Process_Injection", "pattern": rb"(?:NtWriteVirtualMemory|NtCreateThreadEx|NtMapViewOfSection|QueueUserAPC|RtlCreateUserThread)", "severity": "HIGH"},
    {"name": "Keylogger_APIs", "pattern": rb"(?:GetAsyncKeyState|SetWindowsHookEx|GetKeyState|GetKeyboardState)", "severity": "HIGH"},
    {"name": "Credential_Dumping", "pattern": rb"(?:sekurlsa::|lsadump::|token::elevate|mimikatz|SAM.*SYSTEM)", "severity": "CRITICAL"},
    {"name": "Ransomware_Note", "pattern": rb"(?:your files? (?:have been|are) encrypt|pay (?:the )?ransom|bitcoin wallet|decrypt(?:ion)? (?:key|tool))", "severity": "CRITICAL"},
    {"name": "Ransomware_UI_Lock", "pattern": rb"(?:fullscreen.*True|overrideredirect.*True|topmost.*True).*(?:encrypt|lock|decrypt|ransom)", "severity": "CRITICAL"},
    {"name": "File_System_Wiper", "pattern": rb"(?:shutil\.rmtree|os\.remove.*glob|del\s+/[sf]\s+\*|format\s+[a-z]:)", "severity": "CRITICAL"},
    {"name": "Shadow_Copy_Deletion", "pattern": rb"(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|bcdedit.*recoveryenabled\s+no)", "severity": "CRITICAL"},
    {"name": "Discord_Exfil", "pattern": rb"discord\.com/api/webhooks", "severity": "CRITICAL"},
    {"name": "Process_Kill_Loop", "pattern": rb"(?:while\s+True|for\s+.*\s+in\s+range\(.*\)).*(?:time\.sleep|proc\.kill|taskkill|kill)", "severity": "HIGH"},
    {"name": "Wallpaper_Hijack", "pattern": rb"(?:SystemParametersInfoW|SPI_SETDESKWALLPAPER|set_desktop_wallpaper|wallpaper.*changed)", "severity": "HIGH"},
    {"name": "Timer_Countdown_Threat", "pattern": rb"(?:timedelta|countdown|time_remaining|end_time).*(?:destroy|delete|lost|gone|expired)", "severity": "CRITICAL"},
    {"name": "Shellcode_Pattern", "pattern": rb"(?:\\x[0-9a-f]{2}){32,}", "severity": "HIGH"},
    {"name": "AMSI_Bypass", "pattern": rb"(?:AmsiUtils|amsiInitFailed|AmsiScanBuffer)", "severity": "HIGH"},
    {"name": "ETW_Patch", "pattern": rb"(?:EtwEventWrite|NtTraceControl|etw.*patch|EventRegister)", "severity": "HIGH"},
    {"name": "Anti_VM_Code", "pattern": rb"(?:VMware|VBox|VirtualBox|QEMU|SbieDll|Sandboxie|wine_get_unix)", "severity": "MEDIUM"},
    {"name": "Macro_Embed_EXE", "pattern": rb"(?:Auto_Open|Document_Open|Workbook_Open).{0,500}?(?:Shell|CreateObject|powershell|cmd\s+/c)", "severity": "HIGH"},
    {"name": "Watchdog_Process", "pattern": rb"(?:subprocess\.Popen.*sys\.argv|os\._exit|os\.kill.*os\.getpid)", "severity": "HIGH"},
    {"name": "Multi_Monitor_Attack", "pattern": rb"(?:get_monitors|secondary_monitors|multi.*monitor|screen.*resolution)", "severity": "MEDIUM"},
    {"name": "User_Data_Targeting", "pattern": rb"(?:Documents|Desktop|Pictures|Downloads|Videos|Music).*(?:os\.walk|glob|listdir|files)", "severity": "CRITICAL"},
    {"name": "File_Lock_Bypass", "pattern": rb"(?:keyboard\.block_key|keyboard\.unhook_all|disable_event|WM_DELETE_WINDOW)", "severity": "HIGH"},
]


def signature_scan(filepath: str, data: bytes = None) -> list:
    matches = []
    try:
        if _is_scanner_or_security_tool(filepath):
            return matches

        if data is None:
            data = open(filepath, "rb").read()
        for rule in SIGNATURE_RULES:
            try:
                if re.search(rule["pattern"], data[:10_000_000], re.IGNORECASE):
                    matches.append({
                        "rule": rule["name"],
                        "severity": rule["severity"],
                    })
            except re.error:
                pass
    except Exception as e:
        log.error(f"Signature scan error: {e}")
    return matches


# ──────────────────────── CLAMAV ENGINE ────────────────────────

def clamav_scan(filepath: str, socket_path: str = "/run/clamav/clamd.ctl",
                tcp_host: str = "127.0.0.1", tcp_port: int = 3310) -> Optional[dict]:
    result = None

    if HAS_PYCLAMD:
        for sock in [socket_path, "/var/run/clamav/clamd.sock", "/tmp/clamd.sock"]:
            try:
                cd = pyclamd.ClamdUnixSocket(sock)
                scan_result = cd.scan_file(filepath)
                if scan_result:
                    return {
                        "engine": "clamav-daemon",
                        "infected": True,
                        "signature": scan_result[1] if isinstance(scan_result, tuple) else str(scan_result),
                        "method": f"unix://{sock}",
                    }
                return {"engine": "clamav-daemon", "infected": False, "method": f"unix://{sock}"}
            except Exception:
                pass

        try:
            cd = pyclamd.ClamdNetworkSocket(tcp_host, tcp_port)
            scan_result = cd.scan_file(filepath)
            if scan_result:
                return {
                    "engine": "clamav-daemon",
                    "infected": True,
                    "signature": scan_result[1] if isinstance(scan_result, tuple) else str(scan_result),
                    "method": f"tcp://{tcp_host}:{tcp_port}",
                }
            return {"engine": "clamav-daemon", "infected": False, "method": f"tcp://{tcp_host}:{tcp_port}"}
        except Exception:
            pass

    clamscan_path = shutil.which("clamscan")
    if clamscan_path:
        try:
            proc = subprocess.run(
                [clamscan_path, "--no-summary", "--infected", filepath],
                capture_output=True, text=True, timeout=120,
            )
            output = proc.stdout.strip()
            if output and filepath in output:
                return {
                    "engine": "clamscan-cli",
                    "infected": True,
                    "signature": output.split(":", 1)[-1].strip() if ":" in output else output,
                    "method": "cli",
                }
            return {"engine": "clamscan-cli", "infected": False, "method": "cli"}
        except FileNotFoundError:
            pass
        except subprocess.TimeoutExpired:
            log.warning("clamscan timed out")
        except Exception as e:
            log.warning(f"clamscan error: {e}")

    return None


# ──────────────────────── VIRUSTOTAL ENGINE ────────────────────────

def virustotal_hash_lookup(hash_val: str, api_key: str = "") -> Optional[dict]:
    if not HAS_REQUESTS:
        return None
    key = api_key or VT_API_KEY
    if not key:
        return None
    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_val}",
            headers={"x-apikey": key}, timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", {}).get("attributes", {})
            stats = data.get("last_analysis_stats", {})
            return {
                "engine": "virustotal-hash",
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0),
                "harmless": stats.get("harmless", 0),
                "total_engines": sum(stats.values()),
                "reputation": data.get("reputation", 0),
                "names": data.get("names", [])[:3],
                "tags": data.get("tags", []),
                "last_analysis_date": data.get("last_analysis_date"),
            }
        elif resp.status_code == 404:
            return {"engine": "virustotal-hash", "status": "not_found"}
        elif resp.status_code == 429:
            log.warning("VirusTotal rate limited")
            return {"engine": "virustotal-hash", "status": "rate_limited"}
        else:
            log.warning(f"VT hash lookup returned {resp.status_code}")
            return None
    except Exception as e:
        log.warning(f"VT hash lookup failed: {e}")
        return None


def virustotal_file_upload(filepath: str, api_key: str = "") -> Optional[dict]:
    if not HAS_REQUESTS:
        return None
    key = api_key or VT_API_KEY
    if not key:
        return None

    file_size = os.path.getsize(filepath)
    if file_size > 32 * 1024 * 1024:
        log.warning(f"File too large for VT upload ({file_size / 1e6:.1f} MB > 32 MB limit)")
        return None

    try:
        url_resp = requests.get(
            "https://www.virustotal.com/api/v3/files/upload_url",
            headers={"x-apikey": key}, timeout=15,
        )
        if url_resp.status_code != 200:
            log.warning(f"VT upload_url returned {url_resp.status_code}")
            return None

        upload_url = url_resp.json().get("data", "")
        if not upload_url:
            return None

        with open(filepath, "rb") as f:
            files = {"file": (os.path.basename(filepath), f)}
            upload_resp = requests.post(
                upload_url,
                headers={"x-apikey": key},
                files=files,
                timeout=120,
            )

        if upload_resp.status_code == 200:
            analysis_id = upload_resp.json().get("data", {}).get("id", "")
            result = {
                "engine": "virustotal-upload",
                "analysis_id": analysis_id,
                "status": "uploaded",
            }

            if analysis_id:
                log.info(f"VT analysis started: {analysis_id}")
                for attempt in range(12):
                    time.sleep(5)
                    try:
                        analysis_resp = requests.get(
                            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                            headers={"x-apikey": key}, timeout=15,
                        )
                        if analysis_resp.status_code == 200:
                            adata = analysis_resp.json().get("data", {}).get("attributes", {})
                            status = adata.get("status", "")
                            if status == "completed":
                                stats = adata.get("stats", {})
                                result.update({
                                    "status": "completed",
                                    "malicious": stats.get("malicious", 0),
                                    "suspicious": stats.get("suspicious", 0),
                                    "undetected": stats.get("undetected", 0),
                                    "harmless": stats.get("harmless", 0),
                                    "total_engines": sum(stats.values()),
                                    "categories": adata.get("results", {}),
                                })
                                detections = []
                                for eng, eng_data in adata.get("results", {}).items():
                                    if eng_data.get("category") in ("malicious", "suspicious"):
                                        detections.append({
                                            "engine": eng,
                                            "result": eng_data.get("result", "unknown"),
                                            "category": eng_data.get("category"),
                                        })
                                result["top_detections"] = detections[:15]
                                break
                            else:
                                log.info(f"  VT analysis status: {status} (attempt {attempt + 1})")
                    except Exception as e:
                        log.warning(f"VT poll error: {e}")

            return result

        elif upload_resp.status_code == 429:
            return {"engine": "virustotal-upload", "status": "rate_limited"}
        else:
            log.warning(f"VT upload returned {upload_resp.status_code}: {upload_resp.text[:200]}")
            return None

    except Exception as e:
        log.warning(f"VT upload failed: {e}")
        return None


# ──────────────────────── FULL SCAN ────────────────────────

def scan_file(filepath: str, malware_db: dict = None, vt_key: str = "",
              skip_vt: bool = False, skip_vt_upload: bool = False,
              skip_clamav: bool = False) -> ScanResult:
    result = ScanResult(filepath)
    start = time.time()

    if not os.path.exists(filepath):
        result.errors.append("File does not exist")
        return result

    result.file_size = os.path.getsize(filepath)
    if result.file_size == 0:
        return result

    if result.file_size > 500_000_000:
        result.errors.append("File too large (>500MB)")
        return result

    log.info(f"Scanning: {filepath} ({result.file_size / 1024:.1f} KB)")

    try:
        result.hashes = compute_hashes(filepath)
        log.info(f"  SHA256: {result.hashes['sha256']}")

        with open(filepath, "rb") as f:
            header = f.read(16)
        result.magic = detect_magic(header)
        result.mime = detect_mime(filepath)

        result.entropy = compute_entropy_analysis(filepath)
        log.info(f"  Entropy: {result.entropy['overall']:.3f} (high_ratio: {result.entropy.get('high_ratio', 0):.2%})")

        ext = os.path.splitext(filepath)[1].lower()
        if ext in (".exe", ".dll", ".sys", ".drv", ".scr", ".cpl") and PEAnalyzer.is_pe(filepath):
            result.pe_info = PEAnalyzer.parse_pe(filepath)
            result.scan_engines.append("pe-analysis")

        if ext in TEXT_EXTENSIONS or result.mime.startswith("text/"):
            result.is_text_file = True
            result.text_findings = text_based_analysis(filepath)
            if result.text_findings:
                crit = sum(1 for f in result.text_findings if f["severity"] == "CRITICAL")
                high = sum(1 for f in result.text_findings if f["severity"] == "HIGH")
                log.warning(f"  Text analysis: {len(result.text_findings)} findings ({crit} CRITICAL, {high} HIGH)")

        if not result.is_text_file:
            result.text_findings = text_based_analysis(filepath)
            if result.text_findings:
                crit = sum(1 for f in result.text_findings if f["severity"] == "CRITICAL")
                log.warning(f"  Behavioral analysis: {len(result.text_findings)} findings ({crit} CRITICAL)")

        result.signature_matches = signature_scan(filepath)
        if result.signature_matches:
            result.scan_engines.append("signatures")
            for sig in result.signature_matches:
                log.warning(f"  Signature: [{sig['severity']}] {sig['rule']}")

        if malware_db:
            for algo in ["md5", "sha1", "sha256"]:
                if result.hashes.get(algo, "").lower() in malware_db.get(algo, set()):
                    result.hash_db_match = True
                    result.scan_engines.append("malware-db")
                    log.critical(f"  *** KNOWN MALWARE DATABASE MATCH ({algo.upper()}) ***")
                    break

        if not skip_clamav:
            clam_result = clamav_scan(filepath)
            if clam_result:
                result.clamav_result = clam_result
                result.scan_engines.append("clamav")
                if clam_result.get("infected"):
                    log.critical(f"  ClamAV: INFECTED - {clam_result.get('signature', 'unknown')}")
                else:
                    log.info(f"  ClamAV: Clean ({clam_result.get('method', '?')})")
            else:
                log.info("  ClamAV: unavailable")

        if not skip_vt and result.hashes.get("sha256"):
            vt_result = virustotal_hash_lookup(result.hashes["sha256"], vt_key)
            if vt_result:
                result.vt_hash_result = vt_result
                result.scan_engines.append("virustotal-hash")
                if vt_result.get("malicious", 0) > 0:
                    log.warning(f"  VT Hash: {vt_result['malicious']}/{vt_result.get('total_engines', '?')} detections")

        if not skip_vt_upload and not skip_vt and result.file_size <= 32 * 1024 * 1024:
            vt_uploaded = virustotal_file_upload(filepath, vt_key)
            if vt_uploaded:
                result.vt_upload_result = vt_uploaded
                result.scan_engines.append("virustotal-upload")
                if vt_uploaded.get("malicious", 0) > 0:
                    log.warning(f"  VT Upload: {vt_uploaded['malicious']}/{vt_uploaded.get('total_engines', '?')} detections")

        result.risk_score, result.risk_level = calculate_risk_score(result)

    except Exception as e:
        result.errors.append(str(e))
        log.error(f"  Scan error: {e}")

    result.scan_time = time.time() - start
    return result


# ──────────────────────── QUARANTINE ────────────────────────

def quarantine_file(filepath: str) -> str:
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dest = os.path.join(QUARANTINE_DIR, f"{ts}_{os.path.basename(filepath)}")
    shutil.move(filepath, dest)
    log.critical(f"Quarantined: {filepath} -> {dest}")
    return dest


# ──────────────────────── REPORTING ────────────────────────

def print_result(result: ScanResult):
    level = result.risk_level
    color = {"CLEAN": C.GREEN, "LOW": C.CYAN, "MEDIUM": C.YELLOW,
             "HIGH": C.RED, "CRITICAL": C.RED + C.BOLD}.get(level, C.RESET)

    print(f"\n{'='*76}")
    print(f"{C.BOLD}FILE:{C.RESET}        {result.filepath}")
    print(f"{C.BOLD}SIZE:{C.RESET}        {result.file_size:,} bytes ({result.file_size / 1024:.1f} KB)")
    print(f"{C.BOLD}TYPE:{C.RESET}        {result.magic} | {result.mime} | {'Text' if result.is_text_file else 'Binary'}")
    print(f"{C.BOLD}ENTROPY:{C.RESET}     {result.entropy.get('overall', 0):.4f} (max: {result.entropy.get('max', 0):.4f})")
    print(f"{'─'*76}")

    print(f"{C.BOLD}HASHES:{C.RESET}")
    for k, v in result.hashes.items():
        print(f"  {k.upper():>6}: {v}")
    print(f"{'─'*76}")

    if result.pe_info:
        print(f"{C.BOLD}PE INFO:{C.RESET}")
        print(f"  Arch: {'64-bit' if result.pe_info.get('is_64bit') else '32-bit'}")
        for sec in result.pe_info.get("sections", []):
            flags = []
            if sec.get("executable"):
                flags.append("EXEC")
            if sec.get("writable"):
                flags.append("WRITE")
            print(f"  {sec['name']:>8}  V:{sec['virtual_size']:>10}  R:{sec['raw_size']:>10}  [{', '.join(flags)}]")
        print(f"{'─'*76}")

    if result.signature_matches:
        print(f"{C.BOLD}SIGNATURE MATCHES:{C.RESET}")
        for sig in result.signature_matches:
            sc = C.RED if sig["severity"] in ("CRITICAL", "HIGH") else C.YELLOW
            print(f"  {sc}[{sig['severity']:>8}]{C.RESET} {sig['rule']}")
        print(f"{'─'*76}")

    if result.text_findings:
        crit = sum(1 for f in result.text_findings if f["severity"] == "CRITICAL")
        high = sum(1 for f in result.text_findings if f["severity"] == "HIGH")
        med = sum(1 for f in result.text_findings if f["severity"] == "MEDIUM")
        print(f"{C.BOLD}BEHAVIORAL ANALYSIS:{C.RESET} {len(result.text_findings)} findings "
              f"({C.RED}{crit} CRITICAL{C.RESET}, {C.YELLOW}{high} HIGH{C.RESET}, {C.BLUE}{med} MEDIUM{C.RESET})")
        for f in result.text_findings[:20]:
            sc = {"CRITICAL": C.RED + C.BOLD, "HIGH": C.RED, "MEDIUM": C.YELLOW, "LOW": C.CYAN}.get(f["severity"], "")
            line_info = f" L{f['line']}" if f.get("line") else ""
            print(f"  {sc}[{f['severity']:>8}]{C.RESET} {f['description']}{C.DIM}{line_info}{C.RESET}")
            if f.get("context"):
                print(f"            {C.DIM}{f['context'][:120]}{C.RESET}")
        if len(result.text_findings) > 20:
            print(f"  {C.DIM}... and {len(result.text_findings) - 20} more findings{C.RESET}")
        print(f"{'─'*76}")

    if result.hash_db_match:
        print(f"{C.RED}{C.BOLD}*** KNOWN MALWARE DATABASE MATCH ***{C.RESET}")
        print(f"{'─'*76}")

    if result.clamav_result:
        clam = result.clamav_result
        if clam.get("infected"):
            print(f"{C.RED}{C.BOLD}CLAMAV:{C.RESET} {C.RED}INFECTED - {clam.get('signature', 'unknown')}{C.RESET}")
        else:
            print(f"{C.GREEN}CLAMAV:{C.RESET} Clean ({clam.get('method', '?')})")
        print(f"{'─'*76}")

    if result.vt_hash_result and "malicious" in result.vt_hash_result:
        vt = result.vt_hash_result
        print(f"{C.BOLD}VT HASH LOOKUP:{C.RESET}")
        print(f"  Malicious:  {C.RED}{vt['malicious']}{C.RESET}/{vt.get('total_engines', '?')}")
        print(f"  Suspicious: {vt.get('suspicious', 0)}/{vt.get('total_engines', '?')}")
        print(f"  Undetected: {vt.get('undetected', 0)}/{vt.get('total_engines', '?')}")
        if vt.get("tags"):
            print(f"  Tags: {', '.join(vt['tags'][:10])}")
        print(f"{'─'*76}")

    if result.vt_upload_result and result.vt_upload_result.get("status") == "completed":
        vt = result.vt_upload_result
        print(f"{C.BOLD}VT FILE UPLOAD:{C.RESET}")
        print(f"  Malicious:  {C.RED}{vt.get('malicious', 0)}{C.RESET}/{vt.get('total_engines', '?')}")
        print(f"  Suspicious: {vt.get('suspicious', 0)}/{vt.get('total_engines', '?')}")
        if vt.get("top_detections"):
            print(f"  Top detections:")
            for d in vt["top_detections"][:10]:
                cat_color = C.RED if d["category"] == "malicious" else C.YELLOW
                print(f"    {cat_color}{d['engine']:>25}: {d['result']}{C.RESET}")
        print(f"{'─'*76}")
    elif result.vt_upload_result and result.vt_upload_result.get("status") == "uploaded":
        print(f"{C.BLUE}VT FILE UPLOAD:{C.RESET} Analysis submitted (ID: {result.vt_upload_result.get('analysis_id', '?')})")
        print(f"{'─'*76}")

    engines_str = ", ".join(result.scan_engines) if result.scan_engines else "heuristics-only"
    print(f"{C.BOLD}RISK SCORE:{C.RESET}  {color}{C.BOLD}{result.risk_score}/100 [{result.risk_level}]{C.RESET}")
    print(f"{C.BOLD}ENGINES:{C.RESET}     {engines_str}")
    print(f"{C.BOLD}SCAN TIME:{C.RESET}   {result.scan_time:.2f}s")
    if result.errors:
        print(f"{C.YELLOW}ERRORS: {', '.join(result.errors)}{C.RESET}")
    print(f"{'='*76}\n")


def save_report(results: list, output_dir: str = None) -> str:
    out_dir = output_dir or REPORT_DIR
    os.makedirs(out_dir, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(out_dir, f"scan_{ts}.json")

    threats = [r for r in results if r.risk_level not in ("CLEAN", "LOW")]
    report = {
        "scanner_version": VERSION,
        "scan_timestamp": datetime.datetime.now().isoformat(),
        "total_files": len(results),
        "threats_found": len(threats),
        "critical": sum(1 for r in results if r.risk_level == "CRITICAL"),
        "high": sum(1 for r in results if r.risk_level == "HIGH"),
        "medium": sum(1 for r in results if r.risk_level == "MEDIUM"),
        "low": sum(1 for r in results if r.risk_level == "LOW"),
        "clean": sum(1 for r in results if r.risk_level == "CLEAN"),
        "engines_used": list(set(e for r in results for e in r.scan_engines)),
        "results": [r.to_dict() for r in results],
    }
    with open(report_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info(f"Report saved: {report_path}")
    return report_path


# ──────────────────────── FILE WATCHER ────────────────────────

if HAS_WATCHDOG:
    class ScanHandler(FileSystemEventHandler):
        def __init__(self, malware_db, vt_key="", auto_quarantine=False,
                     skip_vt=False, skip_vt_upload=False, skip_clamav=False):
            self.malware_db = malware_db
            self.vt_key = vt_key
            self.auto_quarantine = auto_quarantine
            self.skip_vt = skip_vt
            self.skip_vt_upload = skip_vt_upload
            self.skip_clamav = skip_clamav
            self.results = []
            self._processing = set()

        def _should_scan(self, path):
            if os.path.isdir(path) or path in self._processing:
                return False
            if "scanner.log" in path or "quarantine" in path or "reports" in path:
                return False
            if os.path.exists(path) and os.path.getsize(path) == 0:
                return False
            base = os.path.basename(path).lower()
            if base.startswith(".") or base.startswith("~$"):
                return False
            return True

        def on_created(self, event):
            if not event.is_directory:
                self._handle(event.src_path)

        def on_modified(self, event):
            if not event.is_directory:
                self._handle(event.src_path)

        def _handle(self, path):
            if not self._should_scan(path):
                return
            self._processing.add(path)
            time.sleep(1)
            try:
                result = scan_file(path, self.malware_db, self.vt_key,
                                   self.skip_vt, self.skip_vt_upload, self.skip_clamav)
                self.results.append(result)
                print_result(result)
                if result.risk_score >= 75 and self.auto_quarantine:
                    quarantine_file(path)
            except Exception as e:
                log.error(f"Error scanning {path}: {e}")
            finally:
                self._processing.discard(path)


def scan_directory(dirpath, malware_db, vt_key="", skip_vt=False,
                   skip_vt_upload=False, skip_clamav=False, recursive=True):
    results = []
    dirpath = os.path.expanduser(dirpath)
    if not os.path.isdir(dirpath):
        log.error(f"Not a directory: {dirpath}")
        return results

    log.info(f"Scanning directory: {dirpath}")
    for root, dirs, files in os.walk(dirpath):
        dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("quarantine", "reports", "__pycache__", "venv")]
        for fname in files:
            fpath = os.path.join(root, fname)
            if os.path.isfile(fpath):
                result = scan_file(fpath, malware_db, vt_key, skip_vt, skip_vt_upload, skip_clamav)
                results.append(result)
                print_result(result)
        if not recursive:
            break
    return results


def watch_directory(dirpath, malware_db, vt_key="", auto_quarantine=False,
                    skip_vt=False, skip_vt_upload=False, skip_clamav=False):
    if not HAS_WATCHDOG:
        log.error("pip install watchdog")
        return

    dirpath = os.path.expanduser(dirpath)
    os.makedirs(dirpath, exist_ok=True)
    handler = ScanHandler(malware_db, vt_key, auto_quarantine, skip_vt, skip_vt_upload, skip_clamav)
    observer = Observer()
    observer.schedule(handler, dirpath, recursive=True)
    observer.start()

    print(f"\n{'='*76}")
    print(f"{C.BOLD}{C.GREEN}  REAL-TIME FILE SCANNER ACTIVE{C.RESET}")
    print(f"  Watching: {dirpath}")
    print(f"  Engines: heuristics{', clamav' if not skip_clamav else ''}{', vt-hash' if not skip_vt else ''}{', vt-upload' if not skip_vt_upload else ''}")
    print(f"  Auto-quarantine: {'ON' if auto_quarantine else 'OFF'}")
    print(f"  Press Ctrl+C to stop")
    print(f"{'='*76}\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
        log.info("Monitoring stopped.")
        if handler.results:
            save_report(handler.results)
    observer.join()


def main():
    parser = argparse.ArgumentParser(
        description=f"Multi-Engine File Scanner v{VERSION}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s install                              Check & install dependencies
  %(prog)s scan ./suspicious.exe                Scan a file
  %(prog)s scan ~/Downloads                     Scan Downloads folder
  %(prog)s scan ./mal.py --no-vt-upload         Skip VT upload (hash only)
  %(prog)s watch ~/Downloads --quarantine       Watch & auto-quarantine
  %(prog)s watch ~/Desktop --no-vt --no-clamav  Heuristics-only watch
  %(prog)s add-hash sha256 <hash>               Add to malware DB
  %(prog)s db                                   Show DB stats
        """,
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("install", help="Check for and install required packages")

    scan_cmd = sub.add_parser("scan", help="Scan a file or directory")
    scan_cmd.add_argument("path", help="File or directory to scan")
    scan_cmd.add_argument("--no-vt", action="store_true", help="Skip VirusTotal")
    scan_cmd.add_argument("--no-vt-upload", action="store_true", help="Skip VT file upload")
    scan_cmd.add_argument("--no-clamav", action="store_true", help="Skip ClamAV")
    scan_cmd.add_argument("--no-report", action="store_true", help="Skip JSON report")

    watch_cmd = sub.add_parser("watch", help="Watch directory for new files")
    watch_cmd.add_argument("path", nargs="?", default=os.path.join(os.path.expanduser("~"), "Downloads"))
    watch_cmd.add_argument("--quarantine", action="store_true")
    watch_cmd.add_argument("--no-vt", action="store_true")
    watch_cmd.add_argument("--no-vt-upload", action="store_true")
    watch_cmd.add_argument("--no-clamav", action="store_true")

    add_cmd = sub.add_parser("add-hash", help="Add hash to malware DB")
    add_cmd.add_argument("algo", choices=["md5", "sha1", "sha256"])
    add_cmd.add_argument("hash")

    sub.add_parser("db", help="Show malware DB stats")
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    if args.command == "install":
        install_packages_cmd()
        return

    malware_db = load_malware_db()

    if args.command == "scan":
        path = os.path.expanduser(args.path)
        if os.path.isfile(path):
            result = scan_file(path, malware_db, skip_vt=args.no_vt,
                               skip_vt_upload=args.no_vt_upload, skip_clamav=args.no_clamav)
            print_result(result)
            if not args.no_report:
                save_report([result])
        elif os.path.isdir(path):
            results = scan_directory(path, malware_db, skip_vt=args.no_vt,
                                     skip_vt_upload=args.no_vt_upload, skip_clamav=args.no_clamav)
            if results and not args.no_report:
                save_report(results)
                threats = [r for r in results if r.risk_level not in ("CLEAN", "LOW")]
                print(f"\n{C.BOLD}SUMMARY:{C.RESET} {len(results)} files scanned, "
                      f"{C.RED}{len(threats)} threats{C.RESET}")
        else:
            log.error(f"Path not found: {path}")
            sys.exit(1)

    elif args.command == "watch":
        watch_directory(args.path, malware_db, auto_quarantine=args.quarantine,
                        skip_vt=args.no_vt, skip_vt_upload=args.no_vt_upload,
                        skip_clamav=args.no_clamav)

    elif args.command == "add-hash":
        h = args.hash.lower().strip()
        malware_db.setdefault(args.algo, set()).add(h)
        save_malware_db(malware_db)
        print(f"{C.GREEN}Added {args.algo.upper()}: {h}{C.RESET}")

    elif args.command == "db":
        total = sum(len(v) for v in malware_db.values())
        print(f"{C.BOLD}Malware Hash Database:{C.RESET}")
        for a in ["md5", "sha1", "sha256"]:
            print(f"  {a.upper():>6}: {len(malware_db.get(a, set())):>6}")
        print(f"  TOTAL: {total}")


if __name__ == "__main__":
    main()
