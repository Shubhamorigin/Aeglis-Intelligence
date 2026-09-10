# Secure webhook dispatcher.

import hmac
import hashlib
import json
import httpx
import secrets
import time

def generate_webhook_secret() -> str:
    """Generate a webhook secret for a developer dashboard."""
    return f"whsec_{secrets.token_hex(24)}"

def create_hmac_signature(payload: dict, secret: str) -> str:
    """Create a signature that lets the receiver verify the webhook payload."""
    # Serialize without spaces so the signed content is deterministic.
    payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
    secret_bytes = secret.encode('utf-8')
    
    # Sign the payload with HMAC-SHA256.
    signature = hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest()
    return f"v1={signature}"

async def dispatch_webhook(webhook_url: str, webhook_secret: str, event_type: str, scan_data: dict):
    """Post the completed deep-scan result to the developer's server."""
    if not webhook_url or not webhook_secret:
        return # Nothing to send when the webhook is not configured.
        
    # Build the standard webhook payload.
    payload = {
        "event": event_type,              # e.g., "scan.completed", "scan.failed"
        "timestamp": int(time.time()),    # Exact time
        "data": scan_data                 # Threat result (DANGER/SAFE), Reason, etc.
    }

    # Add a signature so the receiver can verify the payload.
    signature = create_hmac_signature(payload, webhook_secret)
    
    # Identify the sender and include the signature in the headers.
    headers = {
        "Content-Type": "application/json",
        "Aeglis-Signature": signature,
        "User-Agent": "Aeglis-Webhook-Engine/1.0"
    }

    # Send asynchronously so the FastAPI event loop is not blocked.
    try:
        # httpx provides the asynchronous HTTP client used here.
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(webhook_url, json=payload, headers=headers)
            print(f"[✅ WEBHOOK] Delivered to {webhook_url}. Status: {response.status_code}")
    except Exception as e:
        print(f"[❌ WEBHOOK ERROR] Delivery failed for {webhook_url}. Reason: {str(e)}")