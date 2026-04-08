import re
import os
import requests
import json
from dotenv import load_dotenv
from supabase import create_client

# 1. Load Environment Variables
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
WEBRISK_API_KEY = os.getenv("WEB_RISK_API_KEY")

# 2. Supabase Initialization (For global threat caching)
supabase = create_client(os.getenv("SB_API_URL"), os.getenv("SB_ANON_KEY"))

# --- SHARED PATTERNS (Global Regex) ---
URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# --- HELPER FUNCTIONS ---
def is_valid_hash(text):
    """Checks if the input string is a valid MD5/SHA-1/SHA-256 hash."""
    text = text.strip()
    return len(text) in [32, 40, 64] and text.isalnum()

# --- CACHE LOGIC (Save & Read) ---

def check_local_cache(indicator):
    """Checks the database to see if this indicator (URL/Hash) was previously flagged."""
    try:
        res = supabase.table("threat_cache").select("*").eq("indicator", indicator).execute()
        if res.data:
            return {
                "risk_level": res.data[0]["threat_type"],
                "reason": f"Falcon Global Cache: Previously flagged by '{res.data[0]['detected_by']}'.",
                "type": "CACHED_RESULT"
            }
    except Exception as e:
        print(f"Cache Read Error: {e}")
    return None

def save_to_cache(indicator, threat_type, detected_by="Falcon System"):
    """Saves dangerous indicators to the database to protect other users instantly."""
    try:
        supabase.table("threat_cache").upsert({
            "indicator": indicator,
            "threat_type": threat_type,
            "detected_by": detected_by
        }).execute()
        print(f"🛡️ Indicator Cached: {indicator}")
    except Exception as e:
        print(f"Cache Save Error: {e}")

# --- API WORKERS (The Detectives) ---

def scan_alienvault(indicator: str, indicator_type: str = "file"):
    """
    Checks AlienVault OTX (100% FREE). 
    indicator_type can be 'file' (hash), 'url', or 'ip'.
    """
    OTX_URL = f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{indicator}/general"
    
    try:
        response = requests.get(OTX_URL)
        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            if pulse_info.get("count", 0) > 0:
                return {
                    "risk_level": "DANGER",
                    "reason": f"AlienVault OTX Alert: Flagged by {pulse_info['count']} security researchers.",
                    "type": "ALIENVAULT_OTX"
                }
        return {"risk_level": "SAFE", "reason": "No threat records found on AlienVault.", "type": "ALIENVAULT_OTX"}
    except Exception as e:
        print(f"AlienVault API Error: {e}")
        return None

def scan_virustotal(file_hash):
    """Checks file reputation using VirusTotal API (Limited Free Tier)."""
    if not VT_API_KEY:
        return {"risk_level": "ERROR", "reason": "VirusTotal API Key missing."}

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious = stats.get('malicious', 0)
            
            if malicious > 0:
                return {
                    "risk_level": "DANGER", 
                    "reason": f"VirusTotal Alert: Flagged as malware by {malicious} security vendors.", 
                    "type": "FILE_HASH"
                }
            return {"risk_level": "SAFE", "reason": "File is clean according to VirusTotal.", "type": "FILE_HASH"}
        elif response.status_code == 404:
            return {"risk_level": "WARNING", "reason": "Unknown Hash. No prior record found.", "type": "FILE_HASH"}
    except Exception as e:
        print(f"VT Error: {e}")
    return {"risk_level": "ERROR", "reason": "VirusTotal connection failed.", "type": "FILE_HASH"}

def scan_webrisk(url_to_check):
    """Verifies link safety using Google Web Risk API."""
    if not WEBRISK_API_KEY:
        return {"risk_level": "ERROR", "reason": "WebRisk API Key missing."}

    base_url = "https://webrisk.googleapis.com/v1/uris:search"
    params = {
        "key": WEBRISK_API_KEY,
        "uri": url_to_check,
        "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"]
    }
    try:
        response = requests.get(base_url, params=params)
        result = response.json()
        if "threat" in result:
            threat_type = result['threat']['threatTypes'][0]
            return {
                "risk_level": "DANGER", 
                "reason": f"Google Security Alert: Unsafe link detected ({threat_type}).", 
                "type": "URL"
            }
        return {"risk_level": "SAFE", "reason": "Google Web Risk found no threats.", "type": "URL"}
    except Exception as e:
        print(f"WebRisk Error: {e}")
    return {"risk_level": "ERROR", "reason": "Google Web Risk scan failed.", "type": "URL"}

def scan_groq_ai(text_message):
    """Analyzes message context using Groq Llama 3.3 model."""
    url = "https://api.groq.com/openai/v1/chat/completions"
    
    if not GROQ_API_KEY:
        return {"risk_level": "ERROR", "reason": "Groq API Key missing.", "type": "TEXT"}

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    
    prompt = """
    You are 'Falcon Detect', an elite AI cybersecurity guard. 
    Analyze the following message for scams, phishing, or social engineering.
    Reply ONLY in this JSON format: {"risk": "DANGER" or "SAFE", "reason": "2-3 line concise reason in English explaining why"}
    """
    
    payload = {
        "model": "llama-3.3-70b-versatile",
        "messages": [
            {"role": "system", "content": prompt}, 
            {"role": "user", "content": text_message}
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"}
    }
    
    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            result = json.loads(response.json()['choices'][0]['message']['content'])
            return {
                "risk_level": result.get("risk", "WARNING"), 
                "reason": result.get("reason", "Analyzed by AI Intelligence."), 
                "type": "TEXT"
            }
    except Exception as e:
        print(f"Groq AI Error: {e}")
    
    return {"risk_level": "ERROR", "reason": "AI Brain is unresponsive.", "type": "TEXT"}


# --- THE MASTER ROUTER (WATERFALL MODEL) ---

def falcon_detect_master_scan(user_input):
    """Main routing engine deciding the scan workflow to save API costs."""
    user_input = user_input.strip()

    # Step 0: Check Local Cache First (Cost: $0)
    cached = check_local_cache(user_input)
    if cached: 
        print("🛡️ Stopped by Local Cache!")
        return cached
    
    # 1. HASH SCAN: If user provided a raw file hash
    if is_valid_hash(user_input):
        # Step 1A: Check AlienVault OTX (Cost: $0)
        alienvault_res = scan_alienvault(user_input, "file")
        if alienvault_res and alienvault_res["risk_level"] == "DANGER":
            save_to_cache(user_input, "DANGER", "AlienVault OTX")
            print("👽 Stopped by AlienVault OTX!")
            return alienvault_res
            
        # Step 1B: VirusTotal as last resort
        print("☣️ Checked via VirusTotal!")
        return scan_virustotal(user_input)
        
    # 2. URL SCAN: If a link is hidden inside the message
    url_found = URL_PATTERN.search(user_input)
    if url_found:
        target_url = url_found.group(0)
        
        # Step 2A: Check AlienVault OTX for URL (Cost: $0)
        alienvault_res = scan_alienvault(target_url, "url")
        if alienvault_res and alienvault_res["risk_level"] == "DANGER":
            save_to_cache(target_url, "DANGER", "AlienVault OTX")
            return alienvault_res
            
        # Step 2B: Check Google Web Risk
        webrisk_res = scan_webrisk(target_url)
        if webrisk_res["risk_level"] == "DANGER":
            save_to_cache(target_url, "DANGER", "Google Web Risk")
            return webrisk_res
            
        # If APIs say the URL is safe, pass the full context to AI
        return scan_groq_ai(user_input)

    # 3. TEXT SCAN: For simple text messages without links or hashes
    return scan_groq_ai(user_input)