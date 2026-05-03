import re
import os
import requests
import json
import csv
from urllib.parse import urlparse
from dotenv import load_dotenv
from utils.supabase_db import supabase_admin

# 1. Load Environment Variables
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
WEBRISK_API_KEY = os.getenv("WEB_RISK_API_KEY")

# --- MASTER WHITELIST (O(1) lookup speed) ---
MASTER_WHITELIST = set()

def load_master_whitelist(filepath="white_listed.csv", limit=10000):
    """
    CSV se Top 1 Lakh pure domains RAM me load karta hai.
    Call this ONLY ONCE when the server starts.
    """
    global MASTER_WHITELIST
    if not os.path.exists(filepath):
        print(f"⚠️ Whitelist warning: '{filepath}' not found. Whitelist is empty.")
        return

    try:
        with open(filepath, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            count = 0
            for row in reader:
                if count >= limit:
                    break
                # row[1] is Column B (The Pure Domain)
                if len(row) > 1:
                    pure_domain = row[1].strip().lower()
                    MASTER_WHITELIST.add(pure_domain)
                    count += 1
        print(f"✅ Loaded {len(MASTER_WHITELIST)} domains into Master Whitelist! (RAM is safe)")
    except Exception as e:
        print(f"❌ Error loading whitelist: {e}")

def extract_pure_domain_from_user_input(url):
    """
    User ke WhatsApp message me aaye link (https://www.youtube.com/watch)
    ko pure domain (youtube.com) me convert karega taaki CSV se match ho sake.
    """
    try:
        # Fix: urlparse needs a scheme to detect netloc correctly.
        # If 'www.google.com' is passed without http/https, it treats it as a path.
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        domain = urlparse(url).netloc
        return domain.replace("www.", "").lower()
    except:
        return ""

# Server start hote hi file load kar lo
load_master_whitelist("white_listed.csv", limit=100000)
URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

def unmask_short_url(url):
    """Follows redirects to find the real destination URL (URL Unfurling with Stealth)."""
    try:
        # BHAUKAL FIX: Add User-Agent to fake a real browser (Bypasses bit.ly anti-bot)
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        
        # Timeout increased to 5 seconds to give redirects breathing room
        response = requests.get(url, allow_redirects=True, timeout=5, stream=True, headers=headers)
        
        print(f"🔗 Unmasked: {url} -> {response.url}")
        return response.url
        
    except requests.exceptions.Timeout:
        print(f"⚠️ Unmasking timeout for {url}: Destination server is too slow or dead.")
        return url # Timeout ho toh original URL return kardo, aage API khud dekh legi
    except Exception as e:
        print(f"⚠️ Unmasking failed for {url}: {e}")
        return url

# --- HELPER FUNCTIONS ---
def is_valid_hash(text):
    """Checks if the input string is a valid MD5/SHA-1/SHA-256 hash."""
    text = text.strip()
    return len(text) in [32, 40, 64] and text.isalnum()

# --- CACHE LOGIC (Save & Read) ---

def check_local_cache(indicator):
    """Checks the database to see if this indicator (URL/Hash) was previously flagged."""
    try:
        res = supabase_admin.table("threat_cache").select("*").eq("indicator", indicator).execute()
        if res.data:
            return {
                "risk_level": res.data[0]["threat_type"],
                "reason": f"Aeglis Global Cache: Previously flagged by '{res.data[0]['detected_by']}'.",
                "type": "CACHED_RESULT"
            }
    except Exception as e:
        print(f"Cache Read Error: {e}")
    return None

def save_to_cache(indicator, threat_type, detected_by="Aeglis System"):
    """Saves dangerous indicators to the database to protect other users instantly."""
    try:
        supabase_admin.table("threat_cache").upsert({
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
    # 🚨 THE FIX: AlienVault API understands 'IPv4', not 'ip'
    api_indicator_type = indicator_type
    if indicator_type == "ip":
        api_indicator_type = "IPv4"

    # Ab URL ekdum sahi banega: /indicators/IPv4/106.55.164.91/general
    OTX_URL = f"https://otx.alienvault.com/api/v1/indicators/{api_indicator_type}/{indicator}/general"
    
    try:
        response = requests.get(OTX_URL)
        if response.status_code == 200:
            data = response.json()
            pulse_info = data.get("pulse_info", {})
            pulse_count = pulse_info.get("count", 0)
            
            # SMART THRESHOLD LOGIC
            if indicator_type == "url" and pulse_count >= 5:
                return {
                    "risk_level": "DANGER",
                    "reason": f"Aeglis Deep-Intel Network Alert: Flagged by {pulse_count} global security nodes.", # BRANDING
                    "type": "Aeglis_DEEP_INTEL"
                }
            elif indicator_type != "url" and pulse_count > 0:
                return {
                    "risk_level": "DANGER",
                    "reason": f"Aeglis Deep-Intel Network Alert: Flagged by {pulse_count} global security nodes.", # BRANDING
                    "type": "AEglis_DEEP_INTEL"
                }
                
        return {"risk_level": "SAFE", "reason": "No major threat records found on Aeglis Deep-Intel Network.", "type": "Aeglis_DEEP_INTEL"}
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
                    "reason": f"Aeglis Autopsy Sandbox Alert: Flagged as malware by {malicious} security vendors.", # BRANDING
                    "type": "Aeglis"
                }
            return {"risk_level": "SAFE", "reason": "File is clean according to Aeglis Autopsy Sandbox.", "type": "AEGLIS_AUTOPSY"}
        elif response.status_code == 404:
            return {"risk_level": "WARNING", "reason": "Unknown Hash. No prior record found.", "type": "AEGLIS_AUTOPSY"}
    except Exception as e:
        print(f"Sandbox Error: {e}")
    return {"risk_level": "ERROR", "reason": "Aeglis Autopsy Sandbox connection failed.", "type": "AEGLIS_AUTOPSY"}

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
                "reason": f"Aeglis SafeLink Engine Alert: Unsafe link detected ({threat_type}).", # BRANDING
                "type": "Aeglis_SAFELINK"
            }
        return {"risk_level": "SAFE", "reason": "Aeglis SafeLink Engine found no threats.", "type": "AEGLIS_SAFELINK"}
    except Exception as e:
        print(f"SafeLink Error: {e}")
    return {"risk_level": "ERROR", "reason": "Aeglis SafeLink Engine scan failed.", "type": "AEGLIS_SAFELINK"}


def scan_groq_ai(text_message, context_flag="", lang="en"):
    """Analyzes message context using Groq Llama 3.3 model with Threat Intel Context."""
    
    # 🚀 The Smart Language Mapper
    language_map = {
        "en": "English", "hi": "Hindi", "es": "Spanish",
        "pt": "Portuguese", "id": "Indonesian", "ar": "Arabic"
    }
    target_language = language_map.get(lang, "English")
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    
    if not GROQ_API_KEY:
        return {"risk_level": "ERROR", "reason": "Aeglis Intelligence Key missing.", "type": "TEXT"}

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    
    prompt = f"""
    You are 'Aeglis', an elite AI cybersecurity guard. 
    Analyze the following user message for scams, phishing, or social engineering.
    
    [THREAT INTELLIGENCE REPORT]
    Previous Scanners found: {context_flag if context_flag else "No external intel. Rely on text analysis."}
    
    STRICT RULES (CRITICAL):
    1. BRANDING: You MUST NEVER mention 'Google', 'AlienVault', 'VirusTotal', or 'WebRisk'. Always attribute findings to 'Aeglis SafeLink Engine', 'Aeglis Deep-Intel Network', or 'Aeglis Autopsy Sandbox'.
    2. RESPECT INTEL: If the Report says 'DANGER', you MUST flag the final risk as DANGER and explain why based on the intel.
    3. WHITELIST SAFEGUARD: If the report says the domain is WHITELISTED, do NOT flag the link. ONLY flag if the text itself is manipulating the user (e.g., asking for OTPs).
    4. IPs WITHOUT CONTEXT: If Aeglis Deep-Intel Network says the IP is SAFE and there is no scam text, mark it SAFE.
    5. CRITICAL TRANSLATION: You MUST write the "reason" field strictly in {target_language}. Do not output the reason in any other language.
    
    Reply ONLY in this JSON format: {{"risk_level": "DANGER" | "SAFE" | "WARNING", "reason": "2-3 lines explaining the final verdict to the user."}}
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
                "risk_level": result.get("risk_level", "WARNING"), 
                "reason": result.get("reason", "Analyzed by AI Intelligence."), 
                "type": "AI_AGGREGATED"
            }
    except Exception as e:
        print(f"Groq AI Error: {e}")
    
    return {"risk_level": "ERROR", "reason": "AI Brain is unresponsive.", "type": "TEXT"}


# --- THE MASTER ROUTER (WATERFALL MODEL) ---

def Aeglis_master_scan(user_input, lang="en"): # 👈 lang accept kiya
    """Main routing engine that gathers ALL intel and passes it to Groq AI. (No internal DB caching)"""
    user_input = user_input.strip()

    # Step 0: Check Local Cache First (Cost: $0)
    cached = check_local_cache(user_input)
    if cached: 
        print("🛡️ Stopped by Aeglis Global Cache!")
        return cached
        
    intel_context = []
    
    # 1. HASH SCAN
    if is_valid_hash(user_input):
        av_res = scan_alienvault(user_input, "file")
        vt_res = scan_virustotal(user_input)
        
        intel_context.append(f"Aeglis Deep-Intel Network: {av_res}")
        intel_context.append(f"Aeglis Autopsy Sandbox: {vt_res}")
        
        return scan_groq_ai(user_input, context_flag=" | ".join(intel_context), lang=lang) # 👈 lang pass kiya
        
    # 2. URL SCAN
    url_found = URL_PATTERN.search(user_input)
    if url_found:
        target_url = url_found.group(0)
        pure_domain = extract_pure_domain_from_user_input(target_url)
        
        KNOWN_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly", "rebrand.ly", "shorturl.at"}
        
        if pure_domain in KNOWN_SHORTENERS:
            target_url = unmask_short_url(target_url)
            pure_domain = extract_pure_domain_from_user_input(target_url) 
            intel_context.append("Notice: A shortened URL was detected and unmasked to reveal its true destination.")
            
        if pure_domain in MASTER_WHITELIST:
            intel_context.append(f"Domain '{pure_domain}' is verified by Aeglis Zero-Latency Trust.")
        else:
            webrisk_res = scan_webrisk(target_url)
            av_res = scan_alienvault(target_url, "url")
            
            intel_context.append(f"Aeglis SafeLink Engine: {webrisk_res}")
            intel_context.append(f"Aeglis Deep-Intel Network: {av_res}")
            
        return scan_groq_ai(user_input, context_flag=" | ".join(intel_context), lang=lang) # 👈 lang pass kiya
        
    # 2.5 IP SCAN
    ip_found = IP_PATTERN.search(user_input)
    if ip_found and not url_found: 
        target_ip = ip_found.group(0)
        av_res = scan_alienvault(target_ip, "ip")
            
        intel_context.append(f"Aeglis Deep-Intel Network IP Check: {av_res}")
        return scan_groq_ai(user_input, context_flag=" | ".join(intel_context), lang=lang) # 👈 lang pass kiya

    # 3. TEXT SCAN (No URLs/IPs/Hashes found)
    return scan_groq_ai(user_input, context_flag="No links or IPs detected. Pure text analysis.", lang=lang) # 👈 lang pass kiya
