# webhook_engine.py
# 🦅 Aeglis: Secure Webhook Dispatcher System

import hmac
import hashlib
import json
import httpx
import secrets
import time

def generate_webhook_secret() -> str:
    """
    Developer ke dashboard ke liye ek naya Webhook Secret generate karta hai.
    (e.g., whsec_123abc...)
    """
    return f"whsec_{secrets.token_hex(24)}"

def create_hmac_signature(payload: dict, secret: str) -> str:
    """
    Developer ko kaise pata chalega ki data Aeglis ne bheja hai kisi hacker ne nahi?
    Ye function data ko developer ke secret se lock karta hai aur ek "Signature" banata hai.
    """
    # Payload ko bina space ke string banate hain (Strict JSON format)
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    secret_bytes = secret.encode('utf-8')
    
    # HMAC-SHA256 se sign karna
    signature = hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest()
    return f"v1={signature}"

async def dispatch_webhook(webhook_url: str, webhook_secret: str, event_type: str, scan_data: dict):
    """
    Ye function Background Task ki tarah chalega.
    Deep-Scan complete hone ke baad result Developer ke server par POST karega.
    """
    if not webhook_url or not webhook_secret:
        return # Agar developer ne dashboard mein webhook set nahi kiya toh kuch mat karo
        
    # Standard Webhook Payload Structure
    payload = {
        "event": event_type,              # e.g., "scan.completed", "scan.failed"
        "timestamp": int(time.time()),    # Exact time
        "data": scan_data                 # Threat result (DANGER/SAFE), Reason, etc.
    }

    # Security Signature banate hain
    signature = create_hmac_signature(payload, webhook_secret)
    
    # Header mein Apna Name aur Signature bhejenge
    headers = {
        "Content-Type": "application/json",
        "Aeglis-Signature": signature,
        "User-Agent": "Aeglis-Webhook-Engine/1.0"
    }

    # Asynchronous request bhejte hain (Taaki tera FastAPI block na ho)
    try:
        # httpx bohot fast aur modern library hai aisi requests ke liye
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(webhook_url, json=payload, headers=headers)
            print(f"[✅ WEBHOOK] Delivered to {webhook_url}. Status: {response.status_code}")
    except Exception as e:
        print(f"[❌ WEBHOOK ERROR] Delivery failed for {webhook_url}. Reason: {str(e)}")