import os
import json
import base64
import hashlib
import magic
import string
from PIL import Image
from PIL.ExifTags import TAGS
from pdfminer.high_level import extract_text
from androguard.misc import AnalyzeAPK
from groq import AsyncGroq

# Importing shared intelligence and cache checker from core_engine
from core_engine import URL_PATTERN, IP_PATTERN, scan_virustotal, scan_webrisk, check_local_cache, scan_alienvault

class FalconEngine:
    def __init__(self, upload_dir="temp_uploads"):
        self.upload_dir = upload_dir
        if not os.path.exists(upload_dir):
            os.makedirs(upload_dir)
            
        # 🚀 Initialize Quant Hopper (Groq Async Client) for internal engine use
        self.groq_client = AsyncGroq(api_key=os.environ.get("GROQ_API_KEY"))

    def _get_file_hash(self, path):
        """Generates SHA-256 fingerprint of the file for VirusTotal and Cache checks."""
        sha256_hash = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            print(f"Hashing Error: {e}")
            return None

    # 🚨 NAYA FEATURE 1: THE SMART AI GATEKEEPER 🚨
    async def _ai_gatekeeper_check(self, path, file_type):
        """Reads a chunk of the unknown file and asks Quant Hopper to score it (Saves VT Limits)"""
        
        # 1. Image Bypass: Images ko text-gatekeeper ki zaroorat nahi, Vision Engine handle karega
        if "image" in file_type:
            print("🖼️ Image detected. Skipping Text Gatekeeper (Vision Engine will handle it).")
            return 1 # Return Safe score to bypass VirusTotal for images

        try:
            with open(path, 'rb') as f:
                # Read first 4KB of data
                raw_chunk = f.read(4096).decode('utf-8', errors='ignore')
                
                # 2. Sanitize Data: Sirf human-readable characters rakho (Garbage filter)
                clean_chunk = ''.join(filter(lambda x: x in string.printable, raw_chunk))
            
            prompt = f"""
            You are an AI Gatekeeper for a malware scanner.
            File Type: {file_type}
            Raw Content Snippet: {clean_chunk[:1500]}
            
            Does this snippet contain any suspicious patterns, obfuscated code, or phishing text?
            Rate suspicion from 1 to 10 (1 = Safe, 10 = Malware/Scam).
            Return ONLY valid JSON: {{"suspicion_score": 1-10}}
            """
            
            completion = await self.groq_client.chat.completions.create(
                messages=[
                    {"role": "system", "content": "Output strict JSON only."},
                    {"role": "user", "content": prompt}
                ],
                model="llama-3.3-70b-versatile",
                response_format={"type": "json_object"}
            )
            
            data = json.loads(completion.choices[0].message.content)
            return data.get("suspicion_score", 5)
            
        except Exception as e:
            print(f"Gatekeeper error: {e}")
            return 8 # Default to high risk so it goes to VirusTotal if AI fails

    async def analyze_file(self, file_path):
        """Entry point: Checks local cache first, then external APIs, then deep autopsy."""
        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)
        file_hash = self._get_file_hash(file_path)
        
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
                    # STEP C: THE AI GATEKEEPER LOGIC (Cost: $0)
                    print("🧠 Hash Unknown. Consulting falcon's Quant Hopper before VT...")
                    ai_score = await self._ai_gatekeeper_check(file_path, file_type)
                    
                    if ai_score >= 7:
                        print(f"⚠️ AI Score {ai_score}/10! Calling VirusTotal API...")
                        vt_report = scan_virustotal(file_hash)
                    else:
                        print(f"✅ AI Score {ai_score}/10. Safe! Saving VirusTotal API limits.")
                        vt_report = {"risk_level": "SAFE", "reason": "Cleared by Falcon's Quant Hopper Gatekeeper"}
        
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
            # 🚀 Image scan is now Async to await the Vision API
            image_report = await self._scan_image(file_path)
            report.update(image_report)
        else:
            report.update(self._scan_generic(file_path))

        return report

    def _scan_pdf(self, path):
        """PDF Autopsy: Extracts hidden JS, Auto-open triggers, and Malicious Links."""
        findings = {"type": "PDF_ANALYSIS", "suspicious_flags": []}
        try:
            content = extract_text(path)
            urls = list(set(URL_PATTERN.findall(content)))
            findings["indicators"] = urls
            
            for url in urls[:5]:
                url_res = check_local_cache(url)
                if not url_res:
                    av_res = scan_alienvault(url, "url")
                    if av_res and av_res["risk_level"] == "DANGER": url_res = av_res
                if not url_res:
                    url_res = scan_webrisk(url)
                if url_res and url_res.get("risk_level") == "DANGER":
                    findings["suspicious_flags"].append(f"MALICIOUS_LINK_DETECTED: {url}")

            with open(path, 'rb') as f:
                raw = f.read()
                if b'/JS' in raw or b'/JavaScript' in raw:
                    findings["suspicious_flags"].append("HIDDEN_JAVASCRIPT_INJECTION")
                if b'/OpenAction' in raw:
                    findings["suspicious_flags"].append("AUTO_EXECUTE_ON_OPEN")
            
            if findings["suspicious_flags"]: findings["threat_detected"] = True
        except Exception as e:
            findings["error"] = f"PDF Autopsy Failed: {str(e)}"
        return findings

    def _scan_apk(self, path):
        """APK Deep Autopsy: Checks permissions and Spyware patterns."""
        findings = {"type": "APK_ADVANCED_SCAN", "risk_score": 0}
        try:
            a, d, dx = AnalyzeAPK(path)
            findings["package"] = a.get_package()
            permissions = a.get_permissions()
            findings["metadata"] = {"permissions_count": len(permissions)}
            
            danger_perms = [
                "android.permission.RECEIVE_SMS", 
                "android.permission.READ_SMS", 
                "android.permission.SEND_SMS",
                "android.permission.SYSTEM_ALERT_WINDOW",
                "android.permission.RECORD_AUDIO",
                "android.permission.ACCESS_FINE_LOCATION"
            ]
            
            findings["high_risk_permissions"] = [p for p in permissions if p in danger_perms]
            
            if findings["high_risk_permissions"]:
                findings["risk_score"] = len(findings["high_risk_permissions"]) * 20
                if findings["risk_score"] > 50: findings["threat_detected"] = True
        except Exception as e:
            findings["error"] = f"APK Analysis Error: {str(e)}"
        return findings

    # 🚨 NAYA FEATURE 2: THE VISION ENGINE (RAM SAVER) 🚨
    async def _scan_image(self, path):
        """Image Forensics + Quant Hopper 4 Scout Vision Analysis"""
        findings = {"type": "GROQ_VISION_SCAN", "metadata": {}, "extracted_text": "", "threat_detected": False}
        try:
            # 1. Standard Forensics (Location Check)
            img = Image.open(path)
            exif = img._getexif()
            if exif:
                findings["metadata"] = {TAGS.get(k, k): str(v) for k, v in exif.items() if isinstance(v, (int, str, float))}
                if 'GPSInfo' in findings["metadata"]:
                    findings["metadata"]["privacy_alert"] = "Geotagged image found (Location leak risk)"

            # 2. Convert Image to Base64
            with open(path, "rb") as image_file:
                base64_image = base64.b64encode(image_file.read()).decode('utf-8')

            # 3. Hit the Vision API
            print("👁️ Sending Image to Quant Hopper 4 Scout...")
            chat_completion = await self.groq_client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a scam detection AI. Extract text from the image and evaluate it for phishing or scams. Output JSON: {'extracted_text': '...', 'suspicion_score': 1-10, 'reason': '...'}"
                    },
                    {
                        "role": "user",
                        "content": [{"type": "image_url", "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"}}]
                    }
                ],
                model="meta-llama/llama-4-scout-17b-16e-instruct",
                response_format={"type": "json_object"}
            )
            
            groq_data = json.loads(chat_completion.choices[0].message.content)
            findings["extracted_text"] = groq_data.get("extracted_text", "")
            
            # Auto-Flag if image contains a scam
            if groq_data.get("suspicion_score", 1) >= 7:
                findings["threat_detected"] = True
                findings["reason"] = groq_data.get("reason", "Scam detected in image text.")
                
        except Exception as e:
            findings["error"] = f"Vision Engine Failed: {str(e)}"
        return findings

    def _scan_generic(self, path):
        """Generic file scan: Regex based sensitive data extraction."""
        findings = {"type": "GENERIC_SCAN", "indicators": []}
        try:
            with open(path, 'rb') as f:
                content = f.read(1024*1024).decode('utf-8', errors='ignore')
                urls = URL_PATTERN.findall(content)
                ips = IP_PATTERN.findall(content)
                findings["indicators"] = list(set(urls + ips))
                
                if any(x in content for x in ["eval(", "base64_decode", "system("]):
                    findings["threat_detected"] = True
                    findings["reason"] = "Code injection keywords detected."
        except Exception as e:
            findings["error"] = str(e)
        return findings