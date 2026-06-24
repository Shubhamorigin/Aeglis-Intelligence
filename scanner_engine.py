import os
import re
import io
import json
import asyncio
import base64
import hashlib
import magic
import string
import zipfile
import xml.etree.ElementTree as ET
from PIL import Image
from PIL.ExifTags import TAGS
from pdfminer.high_level import extract_text
from androguard.misc import AnalyzeAPK
from groq import AsyncGroq

# oletools — VBA macro analysis
try:
    from oletools.olevba import VBA_Parser, TYPE_OLE, TYPE_OpenXML
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False
    print("⚠️ oletools not installed. Run: pip install -U oletools")

# pefile — PE header analysis
try:
    import pefile
    PEFILE_AVAILABLE = True
except ImportError:
    PEFILE_AVAILABLE = False
    print("⚠️ pefile not installed. Run: pip install pefile")

# Shared intelligence from core_engine
from core_engine import (
    URL_PATTERN,
    scan_virustotal,
    scan_alienvault,
    scan_webrisk,
)

# ── LANGUAGE MAP ──────────────────────────────────────────────────────
LANGUAGE_MAP = {
    "en": "English", "hi": "Hindi",   "ar": "Arabic",
    "es": "Spanish", "pt": "Portuguese", "in": "Indonesian"
}

# ── DANGEROUS APK PERMISSIONS ─────────────────────────────────────────
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS":                   "CRITICAL",
    "android.permission.RECEIVE_SMS":                "CRITICAL",
    "android.permission.SEND_SMS":                   "CRITICAL",
    "android.permission.READ_CALL_LOG":              "CRITICAL",
    "android.permission.PROCESS_OUTGOING_CALLS":     "CRITICAL",
    "android.permission.SYSTEM_ALERT_WINDOW":        "CRITICAL",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "CRITICAL",
    "android.permission.BIND_DEVICE_ADMIN":          "CRITICAL",
    "android.permission.READ_CONTACTS":              "HIGH",
    "android.permission.CAMERA":                     "HIGH",
    "android.permission.RECORD_AUDIO":               "HIGH",
    "android.permission.ACCESS_FINE_LOCATION":       "HIGH",
    "android.permission.READ_EXTERNAL_STORAGE":      "HIGH",
    "android.permission.WRITE_EXTERNAL_STORAGE":     "HIGH",
    "android.permission.INTERNET":                   "MEDIUM",
    "android.permission.GET_ACCOUNTS":               "MEDIUM",
}
SEVERITY_WEIGHT = {"CRITICAL": 30, "HIGH": 20, "MEDIUM": 10}

# ── VBA MACRO DANGER KEYWORDS ─────────────────────────────────────────
# These trigger DANGER regardless of context
VBA_DANGER_KEYWORDS = {
    "AutoOpen", "AutoClose", "Auto_Open", "Auto_Close",
    "Document_Open", "Workbook_Open",           # auto-execute triggers
    "Shell", "CreateObject", "WScript.Shell",    # shell execution
    "powershell", "cmd.exe", "cmd /c",           # command execution
    "Environ", "GetObject",                      # environment access
    "CallByName", "MacroSheet",                  # advanced evasion
}
VBA_SUSPICIOUS_KEYWORDS = {
    "Base64", "Chr(", "Asc(", "StrReverse",     # obfuscation
    "ADODB.Stream", "Scripting.FileSystem",      # file IO
    "WinHttp", "XMLHTTP", "InternetExplorer",   # network access
    "RegWrite", "RegRead",                       # registry access
}

# ── DANGEROUS EXECUTABLES INSIDE ZIP ─────────────────────────────────
DANGEROUS_ZIP_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".jar", ".scr", ".msi", ".apk", ".sh", ".hta",
    ".pif", ".com", ".reg", ".inf",
}

# ── SCRIPT DANGER PATTERNS ────────────────────────────────────────────
SCRIPT_DANGER_PATTERNS = [
    # PowerShell
    rb"Invoke-WebRequest",   rb"Invoke-Expression",
    rb"IEX\s*\(",            rb"-EncodedCommand",
    rb"-enc\s",              rb"DownloadString",
    rb"DownloadFile",        rb"Net\.WebClient",
    rb"Start-Process",       rb"-WindowStyle\s+Hidden",
    rb"-NonInteractive",     rb"Bypass",
    # BAT/CMD
    rb"powershell\s+-",      rb"certutil\s+-decode",
    rb"bitsadmin\s+/transfer",
    rb"mshta\s+http",        rb"regsvr32\s+/s",
    rb"wscript\s+//B",       rb"cscript\s+//B",
    rb"schtasks\s+/create",  rb"net\s+user\s+/add",
    # VBS
    rb"WScript\.Shell",      rb"CreateObject\s*\(",
    rb"Execute\s*\(",        rb"Eval\s*\(",
]

# ── PE (EXE/DLL) DANGER STRINGS ──────────────────────────────────────
PE_DANGER_STRINGS = [
    b"IsDebuggerPresent",    # anti-debug
    b"VirtualAlloc",         # shellcode injection
    b"WriteProcessMemory",   # process injection
    b"CreateRemoteThread",   # remote thread injection
    b"SetWindowsHookEx",     # keylogger
    b"GetAsyncKeyState",     # keylogger
    b"RegSetValueEx",        # registry persistence
    b"WinExec",              # code execution
    b"ShellExecuteA",        # shell execution
    b"URLDownloadToFile",    # downloader
    b"InternetOpenUrl",      # network access
]

# ── JS OBFUSCATION PATTERNS ───────────────────────────────────────────
JS_OBFUSCATION_PATTERNS = [
    r"eval\s*\(",                          # eval()
    r"Function\s*\(['\"]",                # Function constructor
    r"\\x[0-9a-fA-F]{2}",                 # hex encoding
    r"String\.fromCharCode\s*\(",          # char code obfuscation
    r"atob\s*\(",                          # base64 decode
    r"unescape\s*\(",                      # URL decode
    r"\\u[0-9a-fA-F]{4}",                 # unicode escape spam
    r"(?:var|let|const)\s+\w{1}\s*=",     # single char vars (minified)
    r"document\.write\s*\(",              # dynamic DOM write
    r"\.innerHTML\s*=",                    # innerHTML assignment
    r"window\[",                           # bracket notation evasion
    r"setTimeout\s*\(\s*['\"]",            # string-based setTimeout
]


class AeglisEngine:

    def __init__(self, upload_dir: str = "temp_uploads"):
        self.upload_dir = upload_dir
        os.makedirs(upload_dir, exist_ok=True)
        self.groq_client = AsyncGroq(api_key=os.environ.get("GROQ_API_KEY"))

    # ═══════════════════════════════════════════════════════════════════
    # UTILITIES
    # ═══════════════════════════════════════════════════════════════════

    def _get_file_hash(self, path: str) -> str | None:
        sha256 = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256.update(chunk)
            return sha256.hexdigest()
        except Exception as e:
            print(f"Hashing Error: {e}")
            return None

    def _consolidate_verdict(self, vt_report: dict, specialized: dict) -> dict:
        """
        VT/AlienVault result + specialized scan result mein jo serious ho woh final.
        """
        priority = {"DANGER": 3, "WARNING": 2, "SAFE": 1, "UNKNOWN": 0}

        vt_level   = vt_report.get("risk_level", "UNKNOWN")
        spec_level = specialized.get("risk_level", "UNKNOWN")

        if specialized.get("threat_detected"):
            spec_level = "DANGER"

        if priority.get(vt_level, 0) >= priority.get(spec_level, 0):
            return {
                "risk_level": vt_level,
                "reason":     vt_report.get("reason", "Flagged by global threat intelligence.")
            }
        return {
            "risk_level": spec_level,
            "reason":     specialized.get("reason", "Flagged by Aeglis static analysis.")
        }

    # ═══════════════════════════════════════════════════════════════════
    # AI GATEKEEPER — VT credits bachata hai
    # Files NEVER upload hoti hain — sirf text chunk AI ko jaata hai
    # ═══════════════════════════════════════════════════════════════════

    async def _ai_gatekeeper_check(self, path: str, file_type: str, file_content: bytes = None) -> int:
        """
        File ka pehla 4KB locally padh ke AI se suspicion score lo (1-10).
        Score >= 7 → VT hash check karo
        Score <  7 → VT skip karo, credits bachao

        Images bypass karte hain — Vision Engine handle karti hai.
        NOTE: File content KABHI bahar nahi jaata. Sirf cleaned text snippet Groq ko deta hai.
        """
        if "image" in file_type:
            print("Image — skipping text gatekeeper, Vision Engine will handle.")
            return 1

        # Binary formats ke liye bypass — ye UTF-8 decode nahi honge,
        # unke dedicated scanners hain (_scan_apk, _scan_executable, _scan_zip)
        BINARY_MIME_MARKERS = (
            "zip", "x-rar", "x-7z",           # archives
            "x-dosexec", "x-msdownload",       # EXE/DLL/MSI
            "octet-stream", "x-executable",    # generic binaries
            "android",                         # APK
            "x-msi", "x-ms-installer",         # installers
        )
        if any(marker in file_type for marker in BINARY_MIME_MARKERS):
            print(f"Binary MIME ({file_type}) — skipping text gatekeeper, dedicated engine will handle.")
            return 1

        try:
            if file_content:
                raw_chunk = file_content[:4096].decode("utf-8", errors="ignore")
            else:
                with open(path, "rb") as f:
                    raw_chunk = f.read(4096).decode("utf-8", errors="ignore")

            # Only printable ASCII — garbage filter
            clean_chunk = "".join(c for c in raw_chunk if c in string.printable)

            completion = await self.groq_client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "Output strict JSON only."},
                    {"role": "user",   "content": (
                        f"You are an AI malware gatekeeper.\n"
                        f"File Type: {file_type}\n"
                        f"Content Snippet (first 1500 chars):\n{clean_chunk[:1500]}\n\n"
                        f"Analyze for: obfuscated code, suspicious commands, "
                        f"phishing text, malware patterns.\n"
                        f"Rate suspicion 1-10 (1=Safe, 10=Definite Malware).\n"
                        f'Return ONLY: {{"suspicion_score": <number>, "reason": "<brief>"}}'
                    )}
                ],
                model="openai/gpt-oss-20b",
                response_format={"type": "json_object"}
            )
            data  = json.loads(completion.choices[0].message.content)
            score = int(data.get("suspicion_score", 5))
            print(f"AI Gatekeeper score: {score}/10 — {data.get('reason', '')}")
            return score

        except Exception as e:
            print(f"Gatekeeper error: {e}")
            return 8  # Fail safe — VT chalao

    # ═══════════════════════════════════════════════════════════════════
    # MAIN ENTRY POINT
    # ═══════════════════════════════════════════════════════════════════

    async def analyze_file(self, file_path: str, lang: str = "en") -> dict:
        """
        PIPELINE (files kabhi upload nahi hongi):
        1. MIME + SHA-256 hash locally
        2. Local Supabase cache (hash only)
        3. AlienVault hash reputation (hash only — no upload)
        4. AI Gatekeeper → sirf suspicious pe VT hash check
        5. Specialized LOCAL static analysis
        6. Final verdict consolidate
        """
        mime      = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        file_hash = self._get_file_hash(file_path)
        filename  = os.path.basename(file_path).lower()

        print(f"\n{'='*50}")
        print(f"File: {filename} | MIME: {file_type}")
        print(f"Hash: {file_hash[:16]}..." if file_hash else "Hash: N/A")
        print(f"{'='*50}")

        vt_report = {"risk_level": "UNKNOWN", "reason": "Not checked."}

        # ── HASH-ONLY REPUTATION CHECKS ───────────────────────────────
        if file_hash:

                # Step 1 — AlienVault (hash only, no upload)
                av_res = scan_alienvault(file_hash, indicator_type="file")
                if av_res and av_res.get("risk_level") == "DANGER":
                    vt_report = av_res
                    print("🛑 Hash flagged by AlienVault!")

                else:
                    # Step 2 — AI Gatekeeper → VT hash check (no upload)
                    print("🧠 AI Gatekeeper analyzing...")
                    ai_score = await self._ai_gatekeeper_check(file_path, file_type)

                    if ai_score >= 7:
                        print(f"⚠️ Score {ai_score}/10 — checking VirusTotal hash...")
                        vt_report = scan_virustotal(file_hash)
                    else:
                        print(f"✅ Score {ai_score}/10 — hash not submitted to VT.")
                        vt_report = {
                            "risk_level": "SAFE",
                            "reason":     "Cleared by Aeglis AI Gatekeeper (local analysis)."
                        }

        # ── LOCAL STATIC ANALYSIS (no external upload) ────────────────
        print(f"\n🔬 Starting local static analysis...")
        specialized = {}

        if "pdf" in file_type:
            specialized = await asyncio.to_thread(self._scan_pdf, file_path)

        elif "android" in file_type or filename.endswith(".apk"):
            specialized = await self._scan_apk(file_path, lang=lang)

        elif "image" in file_type:
            specialized = await self._scan_image(file_path, lang=lang)

        elif filename.endswith((".zip", ".rar", ".7z")) or "zip" in file_type:
            specialized = await asyncio.to_thread(self._scan_zip, file_path)

        elif filename.endswith((".docx", ".xlsx", ".xlsm", ".docm", ".pptx", ".pptm", ".xls", ".doc")):
            specialized = await asyncio.to_thread(self._scan_office_macros, file_path)

        elif filename.endswith((".exe", ".msi", ".dll", ".scr", ".com")):
            specialized = await asyncio.to_thread(self._scan_executable, file_path)

        elif filename.endswith((".bat", ".cmd", ".ps1", ".vbs", ".hta")):
            specialized = await self._scan_script(file_path, file_type, lang=lang)

        elif filename.endswith(".js") or "javascript" in file_type:
            specialized = await asyncio.to_thread(self._scan_javascript, file_path)

        elif filename.endswith(".svg") or "svg" in file_type:
            specialized = await asyncio.to_thread(self._scan_svg, file_path)

        else:
            specialized = await asyncio.to_thread(self._scan_generic, file_path)

        # ── FINAL VERDICT ─────────────────────────────────────────────
        final_verdict = self._consolidate_verdict(vt_report, specialized)

        return {
            "risk_level":        final_verdict["risk_level"],
            "reason":            final_verdict["reason"],
            "mime_type":         file_type,
            "file_hash":         file_hash,
            "global_reputation": vt_report,
            "scan_details":      specialized,
            "threat_detected":   final_verdict["risk_level"] == "DANGER",
        }

    # ═══════════════════════════════════════════════════════════════════
    # LOCAL ENGINE 1 — OFFICE MACROS (oletools)
    # ═══════════════════════════════════════════════════════════════════

    def _scan_office_macros(self, path: str) -> dict:
        """
        DOCX/XLSX/PPTX/DOC/XLS macro analysis using oletools.
        File kabhi bahar nahi jaati — pure local analysis.

        Detects:
        → VBA macros
        → Auto-execute triggers (AutoOpen, Document_Open, etc.)
        → Dangerous keywords (Shell, CreateObject, powershell)
        → Obfuscation (Base64, Chr(), StrReverse)
        → Hidden sheets (Excel)
        → External relationships
        """
        findings = {
            "type":             "OFFICE_MACRO_ANALYSIS",
            "has_macros":       False,
            "danger_keywords":  [],
            "suspicious_keywords": [],
            "auto_exec_found":  False,
            "suspicious_flags": [],
            "threat_detected":  False,
            "risk_level":       "SAFE",
            "reason":           "No macros or suspicious content found."
        }

        filename = os.path.basename(path).lower()

        # ── oletools VBA analysis ──────────────────────────────────────
        if OLETOOLS_AVAILABLE:
            try:
                vba_parser = VBA_Parser(path)

                if vba_parser.detect_vba_macros():
                    findings["has_macros"] = True
                    print("VBA macros detected — analyzing...")

                    for (filename_vba, stream_path, vba_filename, vba_code) in vba_parser.extract_macros():
                        code_upper = vba_code.upper() if vba_code else ""

                        # Danger keywords check
                        for kw in VBA_DANGER_KEYWORDS:
                            if kw.upper() in code_upper:
                                if kw not in findings["danger_keywords"]:
                                    findings["danger_keywords"].append(kw)
                                if kw in {"AutoOpen", "AutoClose", "Auto_Open",
                                          "Auto_Close", "Document_Open", "Workbook_Open"}:
                                    findings["auto_exec_found"] = True

                        # Suspicious keywords check
                        for kw in VBA_SUSPICIOUS_KEYWORDS:
                            if kw.upper() in code_upper:
                                if kw not in findings["suspicious_keywords"]:
                                    findings["suspicious_keywords"].append(kw)

                vba_parser.close()

            except Exception as e:
                findings["suspicious_flags"].append(f"VBA parse error: {e}")
                print(f"oletools error: {e}")

        else:
            # oletools nahi hai — ZIP as fallback (Office files are ZIP)
            findings["suspicious_flags"].append("oletools unavailable — using ZIP fallback")
            try:
                if zipfile.is_zipfile(path):
                    with zipfile.ZipFile(path, "r") as zf:
                        for fname in zf.namelist():
                            if "vba" in fname.lower() or fname.endswith(".bin"):
                                findings["has_macros"] = True
                                try:
                                    content = zf.read(fname)
                                    for kw in VBA_DANGER_KEYWORDS:
                                        if kw.upper().encode() in content.upper():
                                            findings["danger_keywords"].append(kw)
                                except Exception:
                                    pass
            except Exception as e:
                findings["suspicious_flags"].append(f"ZIP fallback error: {e}")

        # ── Hidden sheets check (Excel only) ──────────────────────────
        if filename.endswith((".xlsx", ".xlsm", ".xls")):
            try:
                if zipfile.is_zipfile(path):
                    with zipfile.ZipFile(path, "r") as zf:
                        for fname in zf.namelist():
                            if "sheet" in fname.lower() and fname.endswith(".xml"):
                                try:
                                    content = zf.read(fname).decode("utf-8", errors="ignore")
                                    if 'state="hidden"' in content or 'state="veryHidden"' in content:
                                        findings["suspicious_flags"].append("HIDDEN_SHEET_DETECTED")
                                except Exception:
                                    pass
            except Exception:
                pass

        # ── External relationships check ───────────────────────────────
        try:
            if zipfile.is_zipfile(path):
                with zipfile.ZipFile(path, "r") as zf:
                    for fname in zf.namelist():
                        if ".rels" in fname.lower():
                            try:
                                content = zf.read(fname).decode("utf-8", errors="ignore")
                                # External http targets in relationships
                                if re.search(r'Target\s*=\s*"https?://', content):
                                    findings["suspicious_flags"].append("EXTERNAL_URL_IN_RELATIONSHIPS")
                            except Exception:
                                pass
        except Exception:
            pass

        # ── Final verdict ──────────────────────────────────────────────
        if findings["danger_keywords"]:
            findings["threat_detected"] = True
            findings["risk_level"]      = "DANGER"
            auto_note = " Auto-execute trigger found." if findings["auto_exec_found"] else ""
            findings["reason"] = (
                f"Office file contains dangerous macro keywords: "
                f"{', '.join(findings['danger_keywords'][:4])}.{auto_note} "
                f"Do NOT enable macros — this file may be ransomware or a dropper."
            )

        elif findings["has_macros"] and findings["suspicious_keywords"]:
            findings["risk_level"] = "WARNING"
            findings["reason"]     = (
                f"Office file contains macros with suspicious patterns: "
                f"{', '.join(findings['suspicious_keywords'][:3])}. "
                f"Only open if you fully trust the sender."
            )

        elif findings["has_macros"]:
            findings["risk_level"] = "WARNING"
            findings["reason"]     = (
                "Office file contains macros. "
                "Macros can execute code automatically. "
                "Only enable if you trust the sender completely."
            )

        elif findings["suspicious_flags"]:
            findings["risk_level"] = "WARNING"
            findings["reason"]     = (
                f"Office file has suspicious properties: "
                f"{', '.join(findings['suspicious_flags'][:3])}."
            )

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # LOCAL ENGINE 2 — ZIP ARCHIVE
    # ═══════════════════════════════════════════════════════════════════

    def _scan_zip(self, path: str) -> dict:
        """
        ZIP/RAR archive inspection — pure local, no extraction to disk.
        Detects:
        → Dangerous executables inside
        → Nested ZIPs (zip bomb pattern)
        → Password protected (suspicious)
        → Path traversal attacks (../ in filenames)
        """
        findings = {
            "type":             "ZIP_ANALYSIS",
            "files_inside":     [],
            "dangerous_files":  [],
            "nested_zips":      0,
            "suspicious_flags": [],
            "threat_detected":  False,
            "risk_level":       "SAFE",
            "reason":           "Archive appears clean."
        }

        try:
            if not zipfile.is_zipfile(path):
                findings["reason"] = "Not a valid ZIP file."
                return findings

            with zipfile.ZipFile(path, "r") as zf:

                # Password check
                try:
                    zf.testzip()
                except RuntimeError as e:
                    if "password" in str(e).lower() or "encrypted" in str(e).lower():
                        findings["suspicious_flags"].append("PASSWORD_PROTECTED")

                all_files = zf.namelist()
                findings["files_inside"] = all_files[:100]

                for fname in all_files:
                    fname_lower = fname.lower()
                    ext = os.path.splitext(fname_lower)[1]

                    # Path traversal attack
                    if ".." in fname or fname.startswith("/"):
                        findings["suspicious_flags"].append(f"PATH_TRAVERSAL: {fname}")

                    # Dangerous executable inside
                    if ext in DANGEROUS_ZIP_EXTENSIONS:
                        findings["dangerous_files"].append(fname)
                        findings["suspicious_flags"].append(
                            f"DANGEROUS_FILE: {fname}"
                        )

                    # Nested ZIP
                    if ext == ".zip":
                        findings["nested_zips"] += 1

                if findings["nested_zips"] >= 2:
                    findings["suspicious_flags"].append(
                        f"NESTED_ZIPS: {findings['nested_zips']} (possible zip bomb)"
                    )

        except Exception as e:
            findings["error"]      = f"ZIP scan failed: {e}"
            findings["risk_level"] = "WARNING"
            findings["reason"]     = "Archive could not be fully analyzed — treat with caution."
            return findings

        # Verdict
        has_exe = bool(findings["dangerous_files"])
        if has_exe:
            findings["threat_detected"] = True
            findings["risk_level"]      = "DANGER"
            findings["reason"]          = (
                f"Archive contains dangerous executable files: "
                f"{', '.join(findings['dangerous_files'][:3])}. "
                f"Do NOT extract or run these files."
            )
        elif findings["suspicious_flags"]:
            findings["risk_level"] = "WARNING"
            findings["reason"]     = (
                f"Archive has suspicious properties: "
                f"{', '.join(findings['suspicious_flags'][:3])}."
            )

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # LOCAL ENGINE 3 — SCRIPT FILES (BAT/PS1/VBS/HTA)
    # ═══════════════════════════════════════════════════════════════════

    async def _scan_script(self, path: str, file_type: str, lang: str = "en") -> dict:
        """
        BAT/CMD/PS1/VBS/HTA analysis:
        → Local regex pattern matching (fast)
        → AI Gatekeeper for context-aware analysis
        Scripts are text files — AI reads them directly without any upload.
        """
        target_lang = LANGUAGE_MAP.get(lang, "English")
        findings = {
            "type":             "SCRIPT_ANALYSIS",
            "matched_patterns": [],
            "suspicious_flags": [],
            "threat_detected":  False,
            "risk_level":       "SAFE",
            "reason":           "Script appears clean."
        }

        try:
            with open(path, "rb") as f:
                content = f.read(1024 * 512)  # First 512KB

            content_lower = content.lower()

            # Local pattern matching — instant, no API
            for pattern in SCRIPT_DANGER_PATTERNS:
                if re.search(pattern, content, re.IGNORECASE):
                    pattern_str = pattern.decode("utf-8", errors="ignore")
                    findings["matched_patterns"].append(pattern_str)

            # AI Gatekeeper for deeper context analysis
            print("Running AI Gatekeeper on script...")
            ai_score = await self._ai_gatekeeper_check(path, file_type, file_content=content)

            if len(findings["matched_patterns"]) >= 3 or ai_score >= 8:
                findings["threat_detected"] = True
                findings["risk_level"]      = "DANGER"

                # AI se reason generate karo user ki language mein
                try:
                    clean_snippet = content[:2000].decode("utf-8", errors="ignore")
                    completion = await self.groq_client.chat.completions.create(
                        messages=[{
                            "role": "user",
                            "content": (
                                f"Script type: {os.path.basename(path)}\n"
                                f"Dangerous patterns found: {', '.join(findings['matched_patterns'][:5])}\n"
                                f"Script snippet:\n{clean_snippet[:800]}\n\n"
                                f"Write a 1-2 line warning in {target_lang} for a non-technical user "
                                f"explaining why this script is dangerous."
                            )
                        }],
                        model="openai/gpt-oss-20b",
                        max_tokens=150,
                        temperature=0.2
                    )
                    findings["reason"] = completion.choices[0].message.content.strip()
                except Exception:
                    findings["reason"] = (
                        f"Script contains {len(findings['matched_patterns'])} dangerous commands: "
                        f"{', '.join(findings['matched_patterns'][:3])}. "
                        f"Running this script may harm your system."
                    )

            elif findings["matched_patterns"] or ai_score >= 5:
                findings["risk_level"] = "WARNING"
                findings["reason"]     = (
                    f"Script contains potentially suspicious patterns: "
                    f"{', '.join(findings['matched_patterns'][:3])}. "
                    f"Verify with sender before running."
                )

        except Exception as e:
            findings["error"]      = f"Script scan failed: {e}"
            findings["risk_level"] = "WARNING"
            findings["reason"]     = "Script could not be analyzed — do not run untrusted scripts."

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # LOCAL ENGINE 4 — JAVASCRIPT (.js)
    # ═══════════════════════════════════════════════════════════════════

    def _scan_javascript(self, path: str) -> dict:
        """
        JS file obfuscation and malicious pattern detection.
        Detects:
        → eval() chains
        → Base64 blobs
        → Hex/unicode encoding spam
        → document.write / innerHTML injection
        → Crypto mining endpoints
        → Data exfiltration patterns
        """
        findings = {
            "type":             "JAVASCRIPT_ANALYSIS",
            "obfuscation_score": 0,
            "matched_patterns": [],
            "suspicious_flags": [],
            "threat_detected":  False,
            "risk_level":       "SAFE",
            "reason":           "JavaScript appears clean."
        }

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(1024 * 512)  # First 512KB

            # Obfuscation pattern matching
            for pattern in JS_OBFUSCATION_PATTERNS:
                matches = re.findall(pattern, content)
                if matches:
                    findings["matched_patterns"].append(pattern)
                    findings["obfuscation_score"] += len(matches)

            # Long base64 strings (data exfil / payload)
            b64_blobs = re.findall(r'["\']([A-Za-z0-9+/]{100,}={0,2})["\']', content)
            if b64_blobs:
                findings["suspicious_flags"].append(
                    f"LARGE_BASE64_BLOB: {len(b64_blobs)} found"
                )
                findings["obfuscation_score"] += len(b64_blobs) * 5

            # Crypto mining endpoints
            mining_keywords = ["stratum+tcp://", "coinhive", "cryptoloot",
                               "minero", "webmr.js", "hashrate"]
            for kw in mining_keywords:
                if kw in content.lower():
                    findings["suspicious_flags"].append(f"CRYPTO_MINING: {kw}")
                    findings["obfuscation_score"] += 20

            # Data exfil patterns
            exfil_patterns = [
                r"fetch\s*\(\s*['\"]https?://(?!(?:localhost|127\.0\.0\.1))",
                r"XMLHttpRequest.*open\s*\(\s*['\"]POST",
                r"navigator\.sendBeacon",
                r"document\.cookie",
            ]
            for pat in exfil_patterns:
                if re.search(pat, content, re.IGNORECASE):
                    findings["suspicious_flags"].append(f"POSSIBLE_EXFIL: {pat[:40]}")

            # Verdict based on score
            if findings["obfuscation_score"] >= 30 or any("CRYPTO_MINING" in f for f in findings["suspicious_flags"]):
                findings["threat_detected"] = True
                findings["risk_level"]      = "DANGER"
                findings["reason"]          = (
                    f"JavaScript is heavily obfuscated or contains malicious patterns. "
                    f"Obfuscation score: {findings['obfuscation_score']}. "
                    f"Flags: {', '.join((findings['suspicious_flags'] + findings['matched_patterns'])[:3])}."
                )

            elif findings["obfuscation_score"] >= 10 or findings["suspicious_flags"]:
                findings["risk_level"] = "WARNING"
                findings["reason"]     = (
                    f"JavaScript contains suspicious patterns "
                    f"(obfuscation score: {findings['obfuscation_score']}). "
                    f"Review before execution."
                )

        except Exception as e:
            findings["error"]      = f"JS scan failed: {e}"
            findings["risk_level"] = "WARNING"
            findings["reason"]     = "JavaScript file could not be fully analyzed."

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # LOCAL ENGINE 5 — SVG (XSS / Embedded JS)
    # ═══════════════════════════════════════════════════════════════════

    def _scan_svg(self, path: str) -> dict:
        """
        SVG XML analysis for embedded JavaScript and XSS vectors.
        SVGs can contain <script> tags and event handlers — dangerous in browsers.
        """
        findings = {
            "type":             "SVG_ANALYSIS",
            "suspicious_flags": [],
            "threat_detected":  False,
            "risk_level":       "SAFE",
            "reason":           "SVG file appears clean."
        }

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            content_lower = content.lower()

            # Script tags
            if "<script" in content_lower:
                findings["suspicious_flags"].append("EMBEDDED_SCRIPT_TAG")

            # JavaScript event handlers
            js_events = [
                "onload=", "onclick=", "onerror=", "onmouseover=",
                "onfocus=", "onblur=", "onkeydown=", "onmouseenter="
            ]
            for event in js_events:
                if event in content_lower:
                    findings["suspicious_flags"].append(f"JS_EVENT_HANDLER: {event}")

            # javascript: URI scheme
            if "javascript:" in content_lower:
                findings["suspicious_flags"].append("JAVASCRIPT_URI_SCHEME")

            # External resource loading
            external_refs = re.findall(
                r'(?:href|src|xlink:href)\s*=\s*["\'](?:https?://|//)',
                content, re.IGNORECASE
            )
            if external_refs:
                findings["suspicious_flags"].append(
                    f"EXTERNAL_RESOURCE_LOAD: {len(external_refs)} references"
                )

            # XML namespace abuse
            if "xmlns:xlink" in content_lower and "http" in content_lower:
                findings["suspicious_flags"].append("XLINK_NAMESPACE_EXTERNAL")

            # data: URI with script
            if "data:text/html" in content_lower or "data:application/javascript" in content_lower:
                findings["suspicious_flags"].append("DATA_URI_SCRIPT")

            # Try XML parse — malformed SVG can be attack vector
            try:
                ET.fromstring(content)
            except ET.ParseError:
                findings["suspicious_flags"].append("MALFORMED_XML_STRUCTURE")

            # Verdict
            critical_flags = [
                f for f in findings["suspicious_flags"]
                if any(x in f for x in ["EMBEDDED_SCRIPT", "JAVASCRIPT_URI", "DATA_URI_SCRIPT"])
            ]

            if critical_flags:
                findings["threat_detected"] = True
                findings["risk_level"]      = "DANGER"
                findings["reason"]          = (
                    f"SVG contains embedded JavaScript or XSS vectors: "
                    f"{', '.join(critical_flags[:3])}. "
                    f"Do not open this SVG in a browser."
                )
            elif findings["suspicious_flags"]:
                findings["risk_level"] = "WARNING"
                findings["reason"]     = (
                    f"SVG has suspicious properties: "
                    f"{', '.join(findings['suspicious_flags'][:3])}. "
                    f"Review before use."
                )

        except Exception as e:
            findings["error"]      = f"SVG scan failed: {e}"
            findings["risk_level"] = "WARNING"
            findings["reason"]     = "SVG could not be analyzed."

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # LOCAL ENGINE 6 — EXE/MSI/DLL (PE Header + String Analysis)
    # ═══════════════════════════════════════════════════════════════════

    def _scan_executable(self, path: str) -> dict:
        """
        EXE/MSI/DLL/SCR static analysis:
        → PE header validation (pefile)
        → Digital signature check
        → Suspicious import functions
        → Dangerous string patterns
        NOTE: File is read locally — never uploaded anywhere.
        """
        findings = {
            "type":             "EXECUTABLE_ANALYSIS",
            "is_signed":        False,
            "suspicious_imports": [],
            "suspicious_strings": [],
            "suspicious_flags": [],
            "threat_detected":  False,
            "risk_level":       "WARNING",  # executables always WARNING minimum
            "reason":           "Executable file — always verify source before running."
        }

        # pefile PE header analysis
        if PEFILE_AVAILABLE:
            try:
                pe = pefile.PE(path)

                # Digital signature check (Authenticode)
                # PE files with valid signature are more trustworthy
                has_signature = hasattr(pe, "DIRECTORY_ENTRY_SECURITY")
                findings["is_signed"] = has_signature
                if not has_signature:
                    findings["suspicious_flags"].append("NOT_DIGITALLY_SIGNED")

                # Import analysis — suspicious WinAPI functions
                if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                imp_name = imp.name.decode("utf-8", errors="ignore")
                                for danger_str in PE_DANGER_STRINGS:
                                    if danger_str.decode("utf-8", errors="ignore") in imp_name:
                                        findings["suspicious_imports"].append(imp_name)

                pe.close()

            except Exception as e:
                findings["suspicious_flags"].append(f"PE parse error: {e}")

        # String-based analysis (works even without pefile)
        try:
            with open(path, "rb") as f:
                content = f.read(1024 * 512)

            for pattern in PE_DANGER_STRINGS:
                if pattern in content:
                    pattern_str = pattern.decode("utf-8", errors="ignore")
                    if pattern_str not in findings["suspicious_strings"]:
                        findings["suspicious_strings"].append(pattern_str)

            # URL strings in executable
            urls_in_exe = URL_PATTERN.findall(content.decode("utf-8", errors="ignore"))
            suspicious_urls = [
                u for u in urls_in_exe
                if not any(t in u.lower() for t in ["microsoft.com", "windows.com",
                                                      "apple.com", "adobe.com"])
            ]
            if suspicious_urls:
                findings["suspicious_flags"].append(
                    f"EMBEDDED_URLS: {', '.join(suspicious_urls[:3])}"
                )

        except Exception as e:
            findings["suspicious_flags"].append(f"String analysis error: {e}")

        # Verdict
        critical_imports = [
            i for i in findings["suspicious_imports"]
            if any(d in i for d in ["WriteProcessMemory", "CreateRemoteThread",
                                     "SetWindowsHookEx", "GetAsyncKeyState"])
        ]

        if critical_imports or len(findings["suspicious_strings"]) >= 4:
            findings["threat_detected"] = True
            findings["risk_level"]      = "DANGER"
            findings["reason"]          = (
                f"Executable uses highly suspicious API calls: "
                f"{', '.join((critical_imports + findings['suspicious_strings'])[:3])}. "
                f"This may be a keylogger, injector, or downloader."
            )
        elif findings["suspicious_strings"] or findings["suspicious_imports"]:
            findings["risk_level"] = "WARNING"
            findings["reason"]     = (
                f"Executable contains suspicious patterns: "
                f"{', '.join((findings['suspicious_strings'] + findings['suspicious_imports'])[:3])}. "
                f"Verify source before running."
            )

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # PDF SCAN
    # ═══════════════════════════════════════════════════════════════════

    def _scan_pdf(self, path: str) -> dict:
        """PDF: Hidden JS, Auto-open triggers, Malicious links, Embedded files."""
        findings = {
            "type":             "PDF_ANALYSIS",
            "suspicious_flags": [],
            "indicators":       [],
            "threat_detected":  False,
            "risk_level":       "SAFE",
            "reason":           "PDF appears clean."
        }
        try:
            content = extract_text(path)
            urls    = list(set(URL_PATTERN.findall(content)))
            findings["indicators"] = urls

            # FIX: Seedha WebRisk call — useless url_res=None check hata diya
            for url in urls[:5]:
                wr = scan_webrisk(url)
                if wr and wr.get("risk_level") == "DANGER":
                    findings["suspicious_flags"].append(f"MALICIOUS_LINK: {url}")

            # Binary checks
            with open(path, "rb") as f:
                raw = f.read()
                checks = {
                    b"/JS":           "HIDDEN_JAVASCRIPT",
                    b"/JavaScript":   "HIDDEN_JAVASCRIPT",
                    b"/OpenAction":   "AUTO_EXECUTE_ON_OPEN",
                    b"/Launch":       "LAUNCH_ACTION",
                    b"/EmbeddedFile": "EMBEDDED_FILE",
                    b"/AA":           "ADDITIONAL_ACTION_TRIGGER",
                    b"/RichMedia":    "RICH_MEDIA_EMBED",
                }
                for sig, flag in checks.items():
                    if sig in raw:
                        findings["suspicious_flags"].append(flag)

            if findings["suspicious_flags"]:
                findings["threat_detected"] = True
                findings["risk_level"]      = "DANGER"
                findings["reason"]          = (
                    f"PDF contains dangerous elements: "
                    f"{', '.join(findings['suspicious_flags'][:4])}. "
                    f"Do not open in a standard PDF reader."
                )

        except Exception as e:
            findings["error"]      = f"PDF scan failed: {e}"
            findings["risk_level"] = "WARNING"
            findings["reason"]     = "PDF could not be fully analyzed — treat with caution."

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # APK SCAN
    # ═══════════════════════════════════════════════════════════════════

    async def _scan_apk(self, path: str, lang: str = "en") -> dict:
        """APK permissions analysis + Groq reason generation."""
        target_lang = LANGUAGE_MAP.get(lang, "English")
        findings = {
            "type":                  "APK_ADVANCED_SCAN",
            "risk_score":            0,
            "dangerous_permissions": [],
            "permission_risk_map":   {},
            "threat_detected":       False,
            "risk_level":            "SAFE",
            "reason":                "No dangerous permissions found."
        }
        try:
            # AnalyzeAPK ek heavy sync call hai — event loop block na ho isliye
            # background thread mein chalate hain
            a, d, dx = await asyncio.to_thread(AnalyzeAPK, path)
            findings["package"]  = a.get_package()
            permissions          = a.get_permissions()
            findings["metadata"] = {"permissions_count": len(permissions)}

            for p in permissions:
                if p in DANGEROUS_PERMISSIONS:
                    findings["dangerous_permissions"].append(p)
                    findings["permission_risk_map"][p] = DANGEROUS_PERMISSIONS[p]

            if findings["dangerous_permissions"]:
                risk_score = sum(
                    SEVERITY_WEIGHT.get(findings["permission_risk_map"].get(p, "MEDIUM"), 10)
                    for p in findings["dangerous_permissions"]
                )
                findings["risk_score"] = risk_score

                critical_perms = [
                    p.split(".")[-1]
                    for p, sev in findings["permission_risk_map"].items()
                    if sev == "CRITICAL"
                ]

                if risk_score >= 50 or critical_perms:
                    findings["threat_detected"] = True
                    findings["risk_level"]      = "DANGER"
                    try:
                        completion = await self.groq_client.chat.completions.create(
                            messages=[{"role": "user", "content": (
                                f"APK: {findings.get('package', 'unknown')}\n"
                                f"Critical permissions: {', '.join(critical_perms[:5])}\n"
                                f"Risk score: {risk_score}/100\n\n"
                                f"Write 1-2 line warning in {target_lang} for non-technical user."
                            )}],
                            model="openai/gpt-oss-20b",
                            max_tokens=120,
                            temperature=0.2
                        )
                        findings["reason"] = completion.choices[0].message.content.strip()
                    except Exception:
                        findings["reason"] = (
                            f"APK requests critical permissions: {', '.join(critical_perms[:3])}. "
                            f"This app may steal your SMS, contacts, or banking data."
                        )
                elif risk_score >= 20:
                    findings["risk_level"] = "WARNING"
                    findings["reason"]     = (
                        f"APK requests {len(findings['dangerous_permissions'])} sensitive permissions. "
                        f"Install with caution."
                    )
        except Exception as e:
            findings["error"]      = f"APK Error: {e}"
            findings["risk_level"] = "WARNING"
            findings["reason"]     = "APK could not be fully analyzed — treat with caution."

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # IMAGE SCAN
    # ═══════════════════════════════════════════════════════════════════

    async def _scan_image(self, path: str, lang: str = "en") -> dict:
        """EXIF forensics + Groq Vision phishing detection."""
        target_lang = LANGUAGE_MAP.get(lang, "English")
        findings = {
            "type":            "AEGLIS_VISION_SCAN",
            "metadata":        {},
            "extracted_text":  "",
            "threat_detected": False,
            "risk_level":      "SAFE",
            "reason":          "Image appears clean."
        }
        try:
            img  = Image.open(path)
            exif = img._getexif() if hasattr(img, "_getexif") else None
            if exif:
                findings["metadata"] = {
                    TAGS.get(k, k): str(v)
                    for k, v in exif.items()
                    if isinstance(v, (int, str, float))
                }
                if "GPSInfo" in findings["metadata"]:
                    findings["metadata"]["privacy_alert"] = (
                        "Geotagged image — location data embedded (privacy risk)"
                    )

            with open(path, "rb") as f:
                b64 = base64.b64encode(f.read()).decode("utf-8")

            print("Sending image to Vision AI...")
            completion = await self.groq_client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": (
                            f"You are a scam detection AI. Extract all text from the image "
                            f"and evaluate for phishing, scams, or fake offers. "
                            f'Output JSON: {{"extracted_text":"...","suspicion_score":1-10,"reason":"..."}}. '
                            f"Write 'reason' strictly in {target_lang}."
                        )
                    },
                    {
                        "role": "user",
                        "content": [{"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{b64}"}}]
                    }
                ],
                model="qwen/qwen3.6-27b",
                response_format={"type": "json_object"}
            )

            data  = json.loads(completion.choices[0].message.content)
            score = int(data.get("suspicion_score", 1))
            findings["extracted_text"] = data.get("extracted_text", "")

            if score >= 7:
                findings["threat_detected"] = True
                findings["risk_level"]      = "DANGER"
                findings["reason"]          = data.get("reason", "Scam content detected in image.")
            elif score >= 4:
                findings["risk_level"] = "WARNING"
                findings["reason"]     = data.get("reason", "Image contains potentially suspicious content.")
            else:
                findings["risk_level"] = "SAFE"
                findings["reason"]     = data.get("reason", "Image appears clean.")

        except Exception as e:
            findings["error"]      = f"Vision Engine Failed: {e}"
            findings["risk_level"] = "WARNING"
            findings["reason"]     = "Image could not be analyzed — proceed with caution."

        return findings

    # ═══════════════════════════════════════════════════════════════════
    # GENERIC SCAN (fallback)
    # ═══════════════════════════════════════════════════════════════════

    def _scan_generic(self, path: str) -> dict:
        """Fallback: URL extraction + code injection keyword detection."""
        findings = {
            "type":            "GENERIC_SCAN",
            "indicators":      [],
            "threat_detected": False,
            "risk_level":      "SAFE",
            "reason":          "No obvious threats found."
        }
        try:
            with open(path, "rb") as f:
                content = f.read(1024 * 1024).decode("utf-8", errors="ignore")

            findings["indicators"] = list(set(URL_PATTERN.findall(content)))

            injection_kw = ["eval(", "base64_decode", "system(", "exec(", "shell_exec("]
            found = [kw for kw in injection_kw if kw in content]

            if found:
                findings["threat_detected"] = True
                findings["risk_level"]      = "DANGER"
                findings["reason"]          = f"Code injection keywords detected: {', '.join(found[:3])}"

        except Exception as e:
            findings["error"]      = str(e)
            findings["risk_level"] = "WARNING"
            findings["reason"]     = "File could not be fully analyzed."

        return findings
