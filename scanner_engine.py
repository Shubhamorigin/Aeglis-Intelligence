import os
import hashlib
import magic
from PIL import Image
from PIL.ExifTags import TAGS
from pdfminer.high_level import extract_text
from androguard.misc import AnalyzeAPK

# Importing shared intelligence and cache checker from core_engine
from core_engine import URL_PATTERN, IP_PATTERN, scan_virustotal, scan_webrisk, check_local_cache, scan_alienvault

class FalconEngine:
    def __init__(self, upload_dir="temp_uploads"):
        self.upload_dir = upload_dir
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)

    def _get_file_hash(self, path):
        """Generates SHA-256 fingerprint of the file for VirusTotal and Cache checks."""
        sha256_hash = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                # Read in chunks for large files to prevent memory overload
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Hashing Error: {e}")
            return None

    async def analyze_file(self, file_path):
        """Entry point: Checks local cache first, then external APIs, then deep autopsy."""
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        file_hash = self._get_file_hash(file_path)
        
        # 1. The Money-Saving Waterfall (Cache -> AlienVault -> VirusTotal)
        vt_report = {"risk_level": "UNKNOWN"}
        if file_hash:
            # STEP A: Check Local Cache First (Cost: $0)
            cached_hash = check_local_cache(file_hash)
            if cached_hash:
                vt_report = cached_hash
                print("🛡️ File Hash Stopped by Local Cache!")
            else:
                # STEP B: Check AlienVault OTX (Cost: $0)
                alienvault_res = scan_alienvault(file_hash, "file")
                if alienvault_res and alienvault_res["risk_level"] == "DANGER":
                    vt_report = alienvault_res
                    print("👽 File Hash Stopped by AlienVault OTX!")
                else:
                    # STEP C: Check VirusTotal ONLY as last resort (Saves API Limits)
                    vt_report = scan_virustotal(file_hash)
                    print("☣️ File Hash Checked via VirusTotal!")
        
        report = {
            "mime_type": file_type,
            "file_hash": file_hash,
            "global_reputation": vt_report,
            "indicators": [],
            "threat_detected": vt_report.get("risk_level") == "DANGER",
            "metadata": {}
        }

        # 2. Specialized Scanning based on File Type
        if "pdf" in file_type:
            report.update(self._scan_pdf(file_path))
        elif "android" in file_type or file_path.endswith('.apk'):
            report.update(self._scan_apk(file_path))
        elif "image" in file_type:
            report.update(self._scan_image(file_path))
        else:
            report.update(self._scan_generic(file_path))

        return report

    def _scan_pdf(self, path):
        """PDF Autopsy: Extracts hidden JS, Auto-open triggers, and Malicious Links."""
        findings = {"type": "PDF_ANALYSIS", "suspicious_flags": []}
        try:
            # Extract text and find links
            content = extract_text(path)
            urls = list(set(URL_PATTERN.findall(content)))
            findings["indicators"] = urls
            
            # Cross-check URLs with Global Cache, AlienVault, and Web Risk
            for url in urls[:5]: # Limit to top 5 links for performance
                # Step A: Cache Check
                url_res = check_local_cache(url)
                
                # Step B: AlienVault OTX Check
                if not url_res:
                    av_res = scan_alienvault(url, "url")
                    if av_res and av_res["risk_level"] == "DANGER":
                        url_res = av_res
                        
                # Step C: Google Web Risk Check
                if not url_res:
                    url_res = scan_webrisk(url)
                
                if url_res and url_res.get("risk_level") == "DANGER":
                    findings["suspicious_flags"].append(f"MALICIOUS_LINK_DETECTED: {url}")

            # Raw byte analysis for exploits
            with open(path, 'rb') as f:
                raw = f.read()
                if b'/JS' in raw or b'/JavaScript' in raw:
                    findings["suspicious_flags"].append("HIDDEN_JAVASCRIPT_INJECTION")
                if b'/OpenAction' in raw:
                    findings["suspicious_flags"].append("AUTO_EXECUTE_ON_OPEN")
            
            if findings["suspicious_flags"]:
                findings["threat_detected"] = True

        except Exception as e:
            findings["error"] = f"PDF Autopsy Failed: {str(e)}"
        return findings

    def _scan_apk(self, path):
        """APK Deep Autopsy: Checks permissions and Spyware patterns."""
        findings = {"type": "APK_ADVANCED_SCAN", "risk_score": 0}
        try:
            # AnalyzeAPK extracts core components
            a, d, dx = AnalyzeAPK(path)
            
            findings["package"] = a.get_package()
            permissions = a.get_permissions()
            findings["metadata"] = {"permissions_count": len(permissions)}
            
            # Dangerous permissions that can steal data
            danger_perms = [
                "android.permission.RECEIVE_SMS", 
                "android.permission.READ_SMS", 
                "android.permission.SEND_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW", # Screen overlays
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION"
            ]
            
            findings["high_risk_permissions"] = [p for p in permissions if p in danger_perms]
            
            # Scoring logic
            if findings["high_risk_permissions"]:
                findings["risk_score"] = len(findings["high_risk_permissions"]) * 20
                if findings["risk_score"] > 50:
                    findings["threat_detected"] = True

        except Exception as e:
            findings["error"] = f"APK Analysis Error: {str(e)}"
        return findings

    def _scan_image(self, path):
        """Image Forensics: Extracts location and device info (Exif)."""
        findings = {"type": "IMAGE_SCAN", "metadata": {}}
        try:
            img = Image.open(path)
            exif = img._getexif()
            if exif:
                findings["metadata"] = {TAGS.get(k, k): str(v) for k, v in exif.items()}
                if 'GPSInfo' in findings["metadata"]:
                    findings["metadata"]["privacy_alert"] = "Geotagged image found (Location leak risk)"
        except:
            findings["metadata"] = "No forensic metadata available."
        return findings

    def _scan_generic(self, path):
        """Generic file scan: Regex based sensitive data extraction."""
        findings = {"type": "GENERIC_SCAN", "indicators": []}
        try:
            with open(path, 'rb') as f:
                # Scan only the first 1MB to prevent memory overload
                content = f.read(1024*1024).decode('utf-8', errors='ignore')
                urls = URL_PATTERN.findall(content)
                ips = IP_PATTERN.findall(content)
                findings["indicators"] = list(set(urls + ips))
                
                # Suspicious code patterns
                if any(x in content for x in ["eval(", "base64_decode", "system("]):
                    findings["threat_detected"] = True
                    findings["reason"] = "Code injection keywords detected."
        except Exception as e:
            findings["error"] = str(e)
        return findings