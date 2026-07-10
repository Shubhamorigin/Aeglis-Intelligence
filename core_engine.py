import re
import os
import requests
import json
import csv
import hashlib
import threading
from urllib.parse import urlparse, urljoin
from dotenv import load_dotenv
from utils.supabase_db import supabase_admin
from scan_url import run_url_scanner
from input_classifier import classify_input

from datetime import datetime
import redis

# ── REDIS SETUP ───────────────────────────────────────────────────────
REDIS_CLIENT = None
try:
    # Use Upstash/Redis URL (preferred)
    redis_url = os.getenv("REDIS_URL")
    if not redis_url:
        raise ValueError("REDIS_URL is not set")

    REDIS_CLIENT = redis.from_url(
        redis_url,
        decode_responses=True,
        socket_connect_timeout=2,
    )
    REDIS_CLIENT.ping()
    print("✅ Redis connected.")
except Exception as _re:
    print(f"⚠️ Redis unavailable: {_re}. Supabase cache will be used.")
    REDIS_CLIENT = None

REDIS_TTL = {
    "SAFE":    86400,   # 24 ghante
    "DANGER":  604800,  # 7 din
    "WARNING": 43200,   # 12 ghante
}

ALL_LANGUAGES  = ["en", "hi", "ar", "es", "pt", "in"]
LANGUAGE_NAMES = {
    "en": "English", "hi": "Hindi",   "ar": "Arabic",
    "es": "Spanish", "pt": "Portuguese", "in": "Indonesian"
}





# Cache RDAP results to reduce repeated lookups during high traffic
_DOMAIN_AGE_CACHE = {}

def get_domain_age(domain: str) -> int | None:
    """Return domain age in days using RDAP (Verisign).

    Returns:
        int  >= 0  : valid age in days
        -1         : domain invalid, RDAP returned no registration date, or unparseable date
        None       : transient error (network failure, rate limit) — DO NOT cache, retry later
    """
    if not domain:
        return -1

    domain = domain.strip().lower().strip('.')
    if not domain:
        return -1

    if domain in _DOMAIN_AGE_CACHE:
        return _DOMAIN_AGE_CACHE[domain]

    # ── RDAP LOOKUP ───────────────────────────────────────────────────────
    base_url = "https://rdap.verisign.com/com/v1/domain/"
    url = urljoin(base_url, domain)

    try:
        headers = {
            "User-Agent": "Mozilla/5.0",
            "Accept": "application/json"
        }
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code != 200:
            # Transient: server error, rate-limited, etc.
            # DO NOT cache — caller should treat None as "unknown, try again later."
            print(f"[RDAP] Server returned {response.status_code} for '{domain}'")
            return None

        data = response.json()

    except Exception as e:
        # Transient: network down, timeout, etc.
        print(f"[RDAP] Transient error for '{domain}': {e}")
        return None

    # ── EXTRACT registration date ─────────────────────────────────────────
    if "events" not in data:
        # RDAP succeeded but structure changed — safe to cache as -1
        _DOMAIN_AGE_CACHE[domain] = -1
        return -1

    raw_date = None
    for event in data["events"]:
        if event.get("eventAction") == "registration":
            raw_date = event.get("eventDate")  # e.g. "1997-09-15T04:00:00Z"
            break

    if not raw_date:
        # RDAP responded but registration date genuinely missing
        _DOMAIN_AGE_CACHE[domain] = -1
        return -1

    # ── PARSE + CALCULATE ────────────────────────────────────────────────
    try:
        clean_date_str = raw_date[:10]  # "YYYY-MM-DD"
        creation_date = datetime.strptime(clean_date_str, "%Y-%m-%d")
    except ValueError:
        _DOMAIN_AGE_CACHE[domain] = -1
        return -1

    age_days = (datetime.now() - creation_date).days
    _DOMAIN_AGE_CACHE[domain] = age_days
    print(f"[Domain Age] {domain} - {age_days} days")
    return age_days




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
        print(f"Whitelist warning: '{filepath}' not found. Whitelist is empty.")
        return

    try:
        with open(filepath, mode='r', encoding='utf-8') as file:
            reader = csv.reader(file)
            count = 0
            for row in reader:
                if count >= limit:
                    break
                if len(row) > 1:
                    pure_domain = row[1].strip().lower()
                    MASTER_WHITELIST.add(pure_domain)
                    count += 1
        print(f"Loaded {len(MASTER_WHITELIST)} domains into Master Whitelist! (RAM is safe)")
    except Exception as e:
        print(f"Error loading whitelist: {e}")

def extract_pure_domain_from_user_input(url: str) -> str:
    """Extracts domain from either:
      - full URL: https://gemini.google.com/path
      - host-only: gemini.google.com

    Returns lowercase domain without www.
    """
    try:
        s = (url or "").strip()
        if not s:
            return ""

        # Remove common trailing punctuation/brackets accidentally captured from text.
        s = s.rstrip(",.;:!?)]}")

        # If scheme missing, urlparse() treats it as path; so prepend scheme.
        if not s.startswith(("http://", "https://")):
            s = "https://" + s

        parsed = urlparse(s)
        domain = (parsed.netloc or "").strip().lower()

        # Fallback: if netloc still empty, treat original token as domain.
        if not domain:
            domain = (url or "").strip().lower().rstrip(",.;:!?)]}")

        return domain.replace("www.", "")
    except Exception:
        return ""


def get_base_domain(domain: str) -> str:
    """Best-effort base-domain extraction.

    Examples:
      - gemini.google.com -> google.com
      - mail.google.co.uk -> google.co.uk
    """
    if not domain:
        return ""

    domain = domain.lower().strip(".")
    parts = [p for p in domain.split(".") if p]
    if len(parts) <= 2:
        return domain

    # Common 2-label public suffixes where we need 3 labels total
    two_label_suffixes = {
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "com.au", "net.au", "org.au", "edu.au",
        "co.in", "org.in", "ac.in",
        "com.br", "com.ar", "com.mx",
        "co.jp", "or.jp", "ne.jp",
        "com.sg", "net.sg",
        "com.tr", "net.tr",
    }

    last2 = ".".join(parts[-2:])
    last3 = ".".join(parts[-3:])

    if last2 in two_label_suffixes and len(parts) >= 3:
        return last3

    return ".".join(parts[-2:])

# Server start hote hi file load kar lo
load_master_whitelist("white_listed.csv", limit=100000)
URL_PATTERN = re.compile(
    r'(?:https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})'
)


def unmask_short_url(url):
    """Follows redirects to find the real destination URL."""
    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
        response = requests.get(url, allow_redirects=True, timeout=5, stream=True, headers=headers)
        print(f"Unmasked: {url} -> {response.url}")
        return response.url
    except requests.exceptions.Timeout:
        print(f"Unmasking timeout for {url}: Destination server is too slow or dead.")
        return url
    except Exception as e:
        print(f"Unmasking failed for {url}: {e}")
        return url

# --- HELPER FUNCTIONS ---
def is_valid_hash(text):
    text = text.strip()
    return len(text) in [32, 40, 64] and text.isalnum()

# ── REDIS HELPERS ─────────────────────────────────────────────────────

def get_redis_base_key(user_input: str) -> str:
    """
    URL → base domain se key
    Text/hash → MD5 hash se key
    """
    url_match = URL_PATTERN.search(user_input.strip()) if 'URL_PATTERN' in globals() else None
    if url_match:
        domain = extract_pure_domain_from_user_input(url_match.group(0))
        base   = get_base_domain(domain)
        return f"scan:{base or domain}"
    text_hash = hashlib.md5(user_input.strip().lower().encode()).hexdigest()
    return f"scan:text:{text_hash}"

def redis_get(base_key: str, lang: str) -> dict | None:
    if not REDIS_CLIENT:
        return None
    try:
        val = REDIS_CLIENT.get(f"{base_key}:{lang}")
        if val:
            print(f"✅ Redis HIT: {base_key}:{lang}")
            return json.loads(val)
    except Exception as e:
        print(f"⚠️ Redis GET error: {e}")
    return None

def redis_set(base_key: str, lang: str, risk_level: str, reason: str):
    if not REDIS_CLIENT:
        return
    try:
        ttl = REDIS_TTL.get(risk_level, 86400)
        REDIS_CLIENT.setex(
            f"{base_key}:{lang}",
            ttl,
            json.dumps({"risk_level": risk_level, "reason": reason})
        )
        print(f"💾 Redis SET: {base_key}:{lang} | TTL:{ttl}s")
    except Exception as e:
        print(f"⚠️ Redis SET error: {e}")

def translate_reason_sync(reason_en: str, lang: str) -> str:
    """English reason ko target language mein translate karo — sirf reason, risk_level nahi."""
    if lang == "en" or not reason_en:
        return reason_en
    target_lang = LANGUAGE_NAMES.get(lang, "English")
    try:
        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"},
            json={
                "model": "openai/gpt-oss-20b",
                "messages": [{
                    "role": "user",
                    "content": (
                        f"Translate this cybersecurity warning to {target_lang}. "
                        f"Return ONLY the translated text, no quotes, no explanation:\n\n{reason_en}"
                    )
                }],
                "temperature": 0.1,
                "max_tokens": 200
            },
            timeout=15
        )
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip()
    except Exception as e:
        print(f"⚠️ Translate error ({lang}): {e}")
    return reason_en  # fallback

def background_translate_and_cache(base_key: str, risk_level: str, reason_en: str, skip_lang: str):
    """
    Daemon thread mein baaki 5 languages translate karke Redis mein store karo.
    skip_lang = jo pehle se store ho chuka hai (user ka requested lang)
    """
    for lang in ALL_LANGUAGES:
        if lang == skip_lang:
            continue
        try:
            translated = translate_reason_sync(reason_en, lang)
            redis_set(base_key, lang, risk_level, translated)
        except Exception as e:
            print(f"⚠️ Background translate failed ({lang}): {e}")

def _save_to_redis_and_background_translate(base_key: str, risk_level: str, reason_en: str, user_lang: str) -> str:
    """
    1. English Redis mein store karo
    2. User ki lang agar en nahi → translate + store
    3. Baaki 5 languages → background thread
    Returns: reason in user_lang
    """
    # English store
    redis_set(base_key, "en", risk_level, reason_en)

    user_reason = reason_en
    if user_lang != "en":
        user_reason = translate_reason_sync(reason_en, user_lang)
        redis_set(base_key, user_lang, risk_level, user_reason)

    # Background mein baaki languages
    t = threading.Thread(
        target=background_translate_and_cache,
        args=(base_key, risk_level, reason_en, user_lang),
        daemon=True
    )
    t.start()

    return user_reason

# --- API WORKERS (The Detectives) ---
def scan_virustotal(file_hash):
    """Checks file reputation using VirusTotal API."""
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
                    "reason": f"Aeglis Autopsy Sandbox Alert: Flagged as malware by {malicious} security vendors.",
                    "type": "AEGLIS_AUTOPSY"
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
                "reason": f"Aeglis SafeLink Engine Alert: Unsafe link detected ({threat_type}).",
                "type": "AEGLIS_SAFELINK"
            }
        return {"risk_level": "SAFE", "reason": "Aeglis SafeLink Engine found no blacklist threats.", "type": "AEGLIS_SAFELINK"}
    except Exception as e:
        print(f"SafeLink Error: {e}")
    return {"risk_level": "ERROR", "reason": "Aeglis SafeLink Engine scan failed.", "type": "AEGLIS_SAFELINK"}

def scan_groq_ai(text_message, context_flag="", lang="en"):
    """Analyzes message context using the AI Core with Threat Intel Context."""
    
    language_map = {
        "en": "English", "hi": "Hindi", "es": "Spanish",
        "pt": "Portuguese", "in": "Indonesian", "ar": "Arabic"
    }
    target_language = language_map.get(lang, "English")
    
    url = "https://api.groq.com/openai/v1/chat/completions"
    
    if not GROQ_API_KEY:
        return {"risk_level": "ERROR", "reason": "Aeglis Intelligence Key missing.", "type": "TEXT"}

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}

    prompt = f"""
    You are 'Aeglis', an elite AI cybersecurity guard.
    Analyze the following user input and context for scams, phishing, or social engineering.
    [THREAT INTELLIGENCE & SANDBOX CONTEXT]
    Previous Scanners found: {context_flag if context_flag else "No external intel. Rely on text analysis."}
    STRICT RULES — OVERRIDE EVERYTHING (Domain Age + Redirect):
    1. Domain age rule:
       - If context contains "Very new domain (< 7 days)" => at least risk_level="WARNING".
       - If context also contains ANY other suspicious signal (Redirect chain/JS Behavior/Sandbox Page Text with login/OTP/fake money) => ALWAYS return risk_level="DANGER".
    2. Redirect rule: If context contains "Redirect chain" => at least risk_level="WARNING".
    3. Whitelist rule: If context contains "verified by Aeglis Zero-Latency Trust" or "WHITELISTED" => return risk_level="SAFE" unless context also contains strong malicious cues (credentials lure/OTP theft/fake money/lottery/urgent panic).
    4. ZERO-DAY social engineering: If context contains fake money promises (free money / lottery winner / download to earn / fake giveaway) => ALWAYS return risk_level="DANGER".
    5. GAMBLING & PREDATORY PLATFORMS — mark WARNING:
       - Unrealistic daily earning claims on page text (₹50,000+/day, "earn daily", "earn ₹X,XX,XXX") => risk_level="WARNING".
       - Online casino / betting / gaming platforms asking for Indian phone numbers (+91) on landing page => risk_level="WARNING".
       - Gambling game names detected in page text ("Aviator", "7UP 7DOWN", "Mines", "Spin", "Lucky Wheel", "Squid Game", "Money Coming") => risk_level="WARNING".
       - Referral/invite systems with instant cash rewards ("invite a friend earn ₹500") on landing page => risk_level="WARNING".
       - Prize wheel or lucky draw with phone number collection => risk_level="WARNING".
       - NOTE: These are predatory platforms, not phishing. Mark WARNING not DANGER unless credential harvesting is also present.
    6. BRANDING: You MUST NEVER mention 'Google', 'VirusTotal', 'Playwright', or 'WebRisk'. Always attribute findings to 'Aeglis SafeLink Engine', 'Aeglis Dynamic Sandbox', or 'Aeglis Autopsy Sandbox'.
    7. CRITICAL TRANSLATION: reason MUST be in {target_language} only. Do not output the reason in any other language.
    Reply ONLY in this JSON format:
    {{"risk_level": "DANGER"|"WARNING"|"SAFE", "reason": "2-3 lines explaining the final verdict to the user."}}
    """
    
    payload = {
        "model": "openai/gpt-oss-120b",
        "messages": [
            {"role": "system", "content": prompt}, 
            {"role": "user", "content": f"Input to scan: {text_message}"}
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
        print(f"AI Core Error: {e}")
    
    return {"risk_level": "ERROR", "reason": "AI Brain is unresponsive.", "type": "TEXT"}


def scan_alienvault(indicator: str, indicator_type: str = "file"): 
    """Checks AlienVault OTX (100% FREE) for file hashes or URLs."""

    # 🚨 THE FIX: AlienVault API understands 'IPv4', not 'ip'
    api_indicator_type = indicator_type


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
                    "type": "Aeglis_DEEP_INTEL"
                }
                
        return {"risk_level": "SAFE", "reason": "No major threat records found on Aeglis Deep-Intel Network.", "type": "Aeglis_DEEP_INTEL"}
    except Exception as e:
        print(f"AlienVault API Error: {e}")
        return None
        

# --- THE MASTER ROUTER (WATERFALL MODEL) ---
async def scan_groq_visual_for_phishing(screenshot_b64: str, target_url: str, lang: str = "en"):
    """Runs a Groq vision check to catch visual-only phishing (e.g., fake SBI/HDFC UI)."""
    language_map = {
        "en": "English",
        "hi": "Hindi",
        "es": "Spanish",
        "pt": "Portuguese",
        "in": "Indonesian",
        "ar": "Arabic",
    }
    target_language = language_map.get(lang, "English")

    if not GROQ_API_KEY:
        return {"risk_level": "ERROR", "reason": "Aeglis Intelligence Key missing.", "type": "VISUAL"}

    url = "https://api.groq.com/openai/v1/chat/completions"

    prompt = f"""
You are a cybersecurity analyst for visual phishing detection.
URL: {target_url}

Check if screenshot visually impersonates ANY known brand:
- Indian banks: SBI, HDFC, ICICI, Axis, Kotak, PNB
- Payment: PayPal, Paytm, PhonePe, Google Pay, UPI
- Global: Amazon, Facebook, Google, Apple, Microsoft, Netflix
- Indian govt: IRCTC, Income Tax, UIDAI/Aadhar, EPFO

RULES:
1. Brand UI + mismatched domain → DANGER
2. Fake login/OTP/payment form + unknown domain → DANGER  
3. Clearly normal site → SAFE
4. Uncertain → WARNING

Return ONLY: {{"risk_level": "SAFE"|"WARNING"|"DANGER", "reason": "..."}}
Reason must be in {target_language}.
"""

    headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
    payload = {
        "model": "qwen/qwen3.6-27b",
        "messages": [
            {"role": "system", "content": "You are a professional cybersecurity expert responding strictly in JSON."},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": prompt},
                    {
                        "type": "image_url",
                        "image_url": {"url": f"data:image/jpeg;base64,{screenshot_b64}"},
                    },
                ],
            },
        ],
        "temperature": 0.1,
        "response_format": {"type": "json_object"},
    }

    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        if response.status_code == 200:
            result = json.loads(response.json()["choices"][0]["message"]["content"])
            return {
                "risk_level": result.get("risk_level", "WARNING"),
                "reason": result.get("reason", "Analyzed by visual AI."),
                "type": "VISUAL_AGGREGATED",
            }
    except Exception as e:
        print(f"⚠️ Groq Vision Error: {e}")

    return {"risk_level": "WARNING", "reason": "Visual analysis failed, but URL context may still be suspicious.", "type": "VISUAL"}

# ─────────────────────────────────────────────────────────────────────────────
# PATCH — core_engine.py
#
# Step 1: File ke TOP pe existing imports ke baad yeh line add karo:
#         from input_classifier import classify_input
#
# Step 2: Sirf Aeglis_master_scan function ko replace karo.
#         Baaki kuch nahi badlna — get_domain_age, scan_groq_ai,
#         scan_webrisk, redis helpers, whitelist — sab same.
# ─────────────────────────────────────────────────────────────────────────────

async def Aeglis_master_scan(user_input, lang="en"):

    user_input = user_input.strip()

    # ══════════════════════════════════════════════════════════════════════════
    # STEP -1  INPUT CLASSIFIER  (NEW)
    # ──────────────────────────────────────────────────────────────────────────
    # Scan se pehle ek lightweight AI call (gpt-oss-20b, ~70 tokens) jo batata:
    #   skip_scan      → Bank SMS / OTP = instant SAFE, zero scan
    #   ignore_urgency → Legitimate promo = urgency flag ignore karo
    #   strict_mode    → Scam/suspicious = full strict pipeline
    #   cleaned_input  → UPI VPAs (@kotakpay etc) hata ke URL detector safe karo
    # ══════════════════════════════════════════════════════════════════════════

    classification = classify_input(user_input)

    print(
        f"[Classifier] type={classification['type']} | "
        f"skip={classification['skip_scan']} | "
        f"strict={classification['strict_mode']} | "
        f"ignore_urgency={classification['ignore_urgency']} | "
        f"confidence={classification['confidence']}"
    )

    # ── Instant SAFE — bank SMS, OTP only (NOT normal text) ──────────────────
    if classification["skip_scan"]:
        safe_reasons = {
            "BANK_TRANSACTION": (
                "Legitimate bank transaction alert. "
                "Registered sender ID and standard transaction format verified."
            ),
            "OTP_MESSAGE": (
                "OTP delivery message from a known service. No threat detected."
            ),
        }
        reason_en = safe_reasons.get(
            classification["type"],
            "Input classified as safe by Aeglis Intelligence Layer."
        )
        final_reason = (
            translate_reason_sync(reason_en, lang)
            if lang != "en" else reason_en
        )
        return {
            "risk_level": "SAFE",
            "reason":     final_reason,
            "type":       f"CLASSIFIED_{classification['type']}",
            "scan_mode":  "message",
            "credits_used": 0
        }

    # ── Use cleaned input (UPI VPAs removed) for rest of pipeline ────────────
    user_input_for_scan = classification["cleaned_input"]

    # ── Inject classification context into intel_context ─────────────────────
    # Yeh baad mein scan_groq_ai ke context_flag mein jayega
    classifier_context = []

    classifier_context.append(
        f"INPUT_CLASSIFICATION: {classification['type']} "
        f"(confidence={classification['confidence']})"
    )

    if classification["ignore_urgency"]:
        classifier_context.append(
            "INSTRUCTION: This input is from a known/legitimate source category. "
            "Do NOT treat urgency, FOMO, countdown timers, or promotional tone "
            "as threat signals alone. Real brands use urgency in legitimate offers. "
            "Only mark WARNING/DANGER if URL itself is suspicious or "
            "domain is very new or page shows credential harvesting."
        )

    if not classification["strict_mode"]:
        classifier_context.append(
            "INSTRUCTION: Apply lenient analysis. "
            "Require multiple strong signals before marking WARNING or DANGER."
        )

    if classification.get("has_upi_vpa"):
        classifier_context.append(
            "NOTE: UPI VPA addresses (like name@kotakpay, name@oksbi) were found "
            "and removed before URL analysis. "
            "These are standard Indian payment identifiers — NOT suspicious URLs."
        )

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 0A  WHITELIST PRE-CHECK  (unchanged — O(1) RAM lookup)
    # ══════════════════════════════════════════════════════════════════════════

    _pre_url_match = URL_PATTERN.search(user_input_for_scan)
    if _pre_url_match:
        _pre_domain  = extract_pure_domain_from_user_input(_pre_url_match.group(0))
        _pre_base    = get_base_domain(_pre_domain)
        _pre_is_pure = (
            len(user_input_for_scan.strip()) <= len(_pre_url_match.group(0)) + 5
        )
        if _pre_is_pure and (
            _pre_domain in MASTER_WHITELIST or
            _pre_base   in MASTER_WHITELIST
        ):
            print(f"⚡ WHITELIST PRE-CHECK HIT (pre-Redis): {_pre_domain}")
            return {
                "risk_level": "SAFE",
                "reason":     "Verified Trusted Domain (Aeglis Zero-Latency Trust).",
                "type":       "AEGLIS_WHITELIST"
            }

    # ══════════════════════════════════════════════════════════════════════════
    # STEP 0B  REDIS CHECK  (unchanged)
    # ══════════════════════════════════════════════════════════════════════════

    url_check    = URL_PATTERN.search(user_input_for_scan)
    is_cacheable = bool(url_check)
    base_key     = get_redis_base_key(user_input_for_scan)

    if is_cacheable:
        redis_cached = redis_get(base_key, lang)
        if redis_cached:
            return {
                "risk_level": redis_cached["risk_level"],
                "reason":     redis_cached["reason"],
                "type":       "CACHED_RESULT"
            }
        if lang != "en":
            redis_en = redis_get(base_key, "en")
            if redis_en:
                translated = translate_reason_sync(redis_en["reason"], lang)
                redis_set(base_key, lang, redis_en["risk_level"], translated)
                return {
                    "risk_level": redis_en["risk_level"],
                    "reason":     translated,
                    "type":       "CACHED_RESULT"
                }

    # ══════════════════════════════════════════════════════════════════════════
    # INPUT TYPE DETECT  (on cleaned input)
    # ══════════════════════════════════════════════════════════════════════════

    intel_context = classifier_context  # classifier context already injected

    url_found    = URL_PATTERN.search(user_input_for_scan)
    has_url      = bool(url_found)
    is_pure_url  = has_url and (
        len(user_input_for_scan.strip()) <= len(url_found.group(0)) + 5
    )
    is_mixed     = has_url and not is_pure_url
    is_pure_text = not has_url and not is_valid_hash(user_input_for_scan)

    print(
        f"Input type → pure_url={is_pure_url} | "
        f"mixed={is_mixed} | pure_text={is_pure_text}"
    )

    # ── 1. HASH SCAN ──────────────────────────────────────────────────────────
    if is_valid_hash(user_input_for_scan):
        vt_res = scan_virustotal(user_input_for_scan)
        intel_context.append(f"Aeglis Autopsy Sandbox: {vt_res}")
        result = scan_groq_ai(
            user_input_for_scan,
            context_flag=" | ".join(intel_context),
            lang="en"
        )
        return result

    # ── 2. URL SCAN ───────────────────────────────────────────────────────────
    if has_url:
        target_url  = url_found.group(0)
        pure_domain = extract_pure_domain_from_user_input(target_url)

        KNOWN_SHORTENERS = {
            "bit.ly", "tinyurl.com", "t.co", "is.gd",
            "buff.ly", "ow.ly", "cutt.ly", "rebrand.ly", "shorturl.at"
        }
        if pure_domain in KNOWN_SHORTENERS:
            target_url  = unmask_short_url(target_url)
            pure_domain = extract_pure_domain_from_user_input(target_url)
            intel_context.append(
                "Notice: Shortened URL unmasked to reveal true destination."
            )

        base_domain = get_base_domain(pure_domain)

        # Domain age check
        age_domain_target = get_base_domain(pure_domain) or pure_domain
        age_days = get_domain_age(age_domain_target)

        if age_days is None:
            intel_context.append(
                "Domain age: unknown (WHOIS lookup failed, treat as unverified)"
            )
        elif age_days == -1:
            intel_context.append(
                "Domain age: unknown (no creation date in WHOIS)"
            )
        else:
            intel_context.append(f"Domain age: {age_days} days")
            if age_days < 7:
                intel_context.append(
                    "WARNING: Very new domain (< 7 days). High phishing risk."
                )

        # Whitelist check
        is_whitelisted = (
            pure_domain in MASTER_WHITELIST or
            base_domain in MASTER_WHITELIST
        )

        if is_whitelisted:
            intel_context.append(
                f"Domain '{pure_domain}' verified by Aeglis Zero-Latency Trust."
            )
            if is_mixed:
                intel_context.append(
                    "URL domain is whitelisted but message text may contain scam context."
                )
                intel_context.append(f"Surrounding message text: {user_input_for_scan}")
                result     = scan_groq_ai(
                    user_input_for_scan,
                    context_flag=" | ".join(intel_context),
                    lang="en"
                )
                risk_level = result.get("risk_level", "WARNING")
                reason_en  = result.get("reason", "")
                if risk_level in REDIS_TTL and not is_mixed:
                    result["reason"] = _save_to_redis_and_background_translate(
                        base_key, risk_level, reason_en, lang
                    )
                return result

        # Full scan pipeline
        webrisk_res = scan_webrisk(target_url)
        intel_context.append(f"Aeglis SafeLink Engine: {webrisk_res}")

        print(f"Launching Aeglis Dynamic Sandbox: {target_url}")
        try:
            sandbox_res = await run_url_scanner(target_url)
        except Exception as sandbox_exc:
            intel_context.append(f"Sandbox Error: {sandbox_exc}")
            sandbox_res = {"status": "failed", "error_message": str(sandbox_exc)}

        visual_res     = None
        js_res         = sandbox_res if isinstance(sandbox_res, dict) else {}
        js_behavior    = js_res.get("js_behavior_signals") or {}
        sandbox_threat = bool(js_res.get("threat_detected"))

        if sandbox_res.get("status") == "success":
            text_context    = sandbox_res.get("extracted_text", "")
            network_context = ", ".join(sandbox_res.get("network_traffic") or [])

            intel_context.append(f"Sandbox Page Text: {text_context}")
            intel_context.append(f"Network Domains: {network_context}")
            intel_context.append(
                f"JS Behavior: {json.dumps(js_behavior)[:1000]}"
            )

            redirect_chain = sandbox_res.get("redirect_chain") or []
            if len(redirect_chain) >= 3:
                intel_context.append(
                    f"Redirect chain: {len(redirect_chain)} hops detected."
                )

            screenshot_b64 = sandbox_res.get("screenshot_base64")
            if screenshot_b64:
                visual_res = await scan_groq_visual_for_phishing(
                    screenshot_b64, target_url, lang="en"
                )
        else:
            intel_context.append(
                f"Sandbox Error: {sandbox_res.get('error_message')}"
            )

        if is_mixed:
            surrounding_text = user_input_for_scan.replace(
                url_found.group(0), ""
            ).strip()
            if surrounding_text:
                intel_context.append(
                    f"User message surrounding text: '{surrounding_text}'"
                )
                intel_context.append(
                    "Analyze surrounding text for social engineering, "
                    "urgency tactics, fake money promises, etc."
                )

        # JS threat → force DANGER
        if sandbox_threat:
            reason_en    = (
                "Suspicious runtime behavior detected "
                "(clipboard hijack / redirect / crypto mining / data exfil)."
            )
            final_reason = _save_to_redis_and_background_translate(
                base_key, "DANGER", reason_en, lang
            )
            return {
                "risk_level": "DANGER",
                "reason":     final_reason,
                "type":       "JS_BEHAVIOR"
            }

        # Final AI verdict
        text_res   = scan_groq_ai(
            user_input_for_scan,
            context_flag=" | ".join(intel_context),
            lang="en"
        )
        candidates = [text_res]
        if visual_res:
            candidates.append(visual_res)

        risk_priority = {"DANGER": 3, "WARNING": 2, "SAFE": 1, "ERROR": 0}
        final = sorted(
            candidates,
            key=lambda r: risk_priority.get(r.get("risk_level"), 0),
            reverse=True
        )[0]

        risk_level = final.get("risk_level", "WARNING")
        reason_en  = final.get("reason", "")
        if risk_level in REDIS_TTL and reason_en and not is_mixed:
            final["reason"] = _save_to_redis_and_background_translate(
                base_key, risk_level, reason_en, lang
            )
        return final

    # ── 3. PURE TEXT SCAN ─────────────────────────────────────────────────────
    # Social engineering, job fraud, romance scam, fake govt notice — sab yahan
    intel_context.append("Pure text input — no URL/IP/hash found.")
    intel_context.append(
        "Analyze for: social engineering, fake offers, "
        "urgency tactics, phishing language, job fraud, "
        "romance scam, fake government/police threats, "
        "OTP/PIN/Aadhaar requests, scam patterns."
    )
    result = scan_groq_ai(
        user_input_for_scan,
        context_flag=" | ".join(intel_context),
        lang=lang
    )
    # Pure text Redis mein NAHI save karte — har user ka text unique hota hai
    return result
