import re
import os
import json
import requests
from dotenv import load_dotenv
load_dotenv()  # Yeh missing tha

GROQ_API_KEY = os.getenv("GROQ_API_KEY")

# ── ONLY 2 REGEX — UPI VPA detect + clean ────────────────────────────────────
UPI_VPA_PATTERN = re.compile(
    r'\b[a-zA-Z0-9._-]+@[a-zA-Z0-9]+\b'
)

def has_upi_vpa(text: str) -> bool:
    return bool(UPI_VPA_PATTERN.search(text))

def clean_upi_vpas(text: str) -> str:
    """Remove UPI VPAs before URL detection so they aren't treated as URLs."""
    return UPI_VPA_PATTERN.sub('[UPI_VPA]', text)

# ── AI CLASSIFIER ─────────────────────────────────────────────────────────────

CLASSIFIER_SYSTEM_PROMPT = """You are an input type classifier for Aeglis, an AI cybersecurity app used in India.

Your job: analyze the message and classify it BEFORE the threat scanner runs.
This classification tells the scanner how strict to be.

Use these signals to classify:

SENDER FORMAT:
- DLT registered format (XX-XXXXX-X like JK-BOBSMS-S, VM-HDFCBK-T) = registered Indian telecom sender = likely legitimate
- Well-known brand name in sender = likely legitimate
- Random numbers, unknown format, misspelled brand = suspicious

BANK TRANSACTION signals (all must be present):
- Dr. or Cr. notation + masked account (XXXX1234 or XXXXXX3098) + Ref/Ref No + AvlBal or Available Balance
- These together = real bank transaction alert, NOT a scam
- "Not you? Call 1800XXXX" in bank SMS = legitimate fraud helpline, NOT a scam number

UPI / PAYMENT signals:
- Patterns like name@okaxis, name@oksbi, name@ybl, name@paytm, name@upi, name@kotakpay, name@apl, name@hdfcbank etc = UPI Virtual Payment Address (VPA)
- UPI VPAs are NOT URLs and NOT suspicious — they are standard Indian payment identifiers
- relianceretail2.easebuzz@kotakpay = UPI VPA, completely normal in transaction SMS

OTP signals:
- Contains OTP / One Time Password / verification code / passcode + a 4-8 digit number
- Sent for login, payment confirmation, account verification = legitimate

PROMOTIONAL signals:
- Known brand name (Jio, Airtel, Amazon, Flipkart, Swiggy, Zomato, IRCTC) + real domain = PROMO_LEGIT
- Real brands use urgency/FOMO in offers — this is normal marketing, NOT a scam
- Unknown sender + urgency + no real domain + suspicious link = PROMO_SUSPICIOUS

SOCIAL ENGINEERING signals (NO URL needed — pure text can be scam):
- Fake job offers asking upfront payment or personal details
- Lottery/prize you never entered
- Impersonating government/police/court
- Asking to call a number for urgent matter
- Love/romance scam patterns
- "Your account will be blocked" without proper sender format
- Any request for OTP, password, PIN, Aadhaar from text message

SCAM signals:
- Prize/lottery you didn't enter + click link = SCAM_TEXT
- Job offer with upfront payment = SCAM_TEXT
- Fake urgency + unknown link + financial ask = MIXED_SUSPICIOUS
- Impersonating bank/govt with wrong sender format = MIXED_SUSPICIOUS

OUTPUT — return ONLY valid JSON, no explanation, no markdown:
{
  "type": "BANK_TRANSACTION|OTP_MESSAGE|PROMO_LEGIT|PROMO_SUSPICIOUS|PURE_URL|MIXED_LEGIT|MIXED_SUSPICIOUS|SCAM_TEXT|NORMAL_TEXT",
  "skip_scan": true or false,
  "ignore_urgency": true or false,
  "strict_mode": true or false,
  "has_upi_vpa": true or false,
  "confidence": "high|medium|low",
  "reasoning": "one short line"
}

CRITICAL RULES:
skip_scan=true ONLY for: BANK_TRANSACTION, OTP_MESSAGE
skip_scan=false for: NORMAL_TEXT and ALL other types (social engineering can look normal)
ignore_urgency=true for: BANK_TRANSACTION, OTP_MESSAGE, PROMO_LEGIT, MIXED_LEGIT, PURE_URL
strict_mode=true ONLY for: MIXED_SUSPICIOUS, SCAM_TEXT, PURE_URL"""


def ai_classify_input(user_input: str) -> dict:
    """
    Lightweight AI classification — gpt-oss-20b, ~70 tokens.
    Called before the main threat scan pipeline.
    """
    if not GROQ_API_KEY:
        return {
            "type": "UNKNOWN",
            "skip_scan": False,
            "ignore_urgency": False,
            "strict_mode": False,
            "has_upi_vpa": has_upi_vpa(user_input),
            "confidence": "low",
            "reasoning": "No API key — defaulting to full scan"
        }

    try:
        response = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            },
            json={
                "model": "openai/gpt-oss-20b",
                "messages": [
                    {"role": "system", "content": CLASSIFIER_SYSTEM_PROMPT},
                    {"role": "user", "content": f"Classify this input:\n\n{user_input}"}
                ],
                "temperature": 0.0,
                "max_tokens": 120,
                "response_format": {"type": "json_object"}
            },
            timeout=8
        )

        if response.status_code == 200:
            result = json.loads(
                response.json()["choices"][0]["message"]["content"]
            )
            print(f"[Classifier] {result.get('type')} | "
                  f"confidence={result.get('confidence')} | "
                  f"{result.get('reasoning', '')}")
            return result

    except Exception as e:
        print(f"[Classifier] AI call failed: {e}")

    # Fallback — safe default, do full scan
    return {
        "type": "UNKNOWN",
        "skip_scan": False,
        "ignore_urgency": False,
        "strict_mode": False,
        "has_upi_vpa": has_upi_vpa(user_input),
        "confidence": "low",
        "reasoning": "Classifier failed — defaulting to full scan"
    }


def classify_input(user_input: str) -> dict:
    """
    Master entry point.
    Cleans UPI VPAs, runs AI classifier, returns routing dict.
    """
    cleaned = clean_upi_vpas(user_input)
    result  = ai_classify_input(user_input)

    return {
        "type":           result.get("type", "UNKNOWN"),
        "skip_scan":      bool(result.get("skip_scan", False)),
        "strict_mode":    bool(result.get("strict_mode", False)),
        "ignore_urgency": bool(result.get("ignore_urgency", False)),
        "has_upi_vpa":    bool(result.get("has_upi_vpa", False)) or (cleaned != user_input),
        "confidence":     result.get("confidence", "low"),
        "reasoning":      result.get("reasoning", ""),
        "cleaned_input":  cleaned,
    }
