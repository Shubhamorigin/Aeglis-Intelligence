# security_engine.py
# 🦅 Falcon Detect: API Key Generation and Verification System

import secrets
import hashlib
from fastapi import Security, HTTPException, Header
from fastapi.security.api_key import APIKeyHeader

# Yeh FastAPI ko batata hai ki API Key "Authorization" header mein aayegi
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

def generate_new_api_key():
    """
    Ek brand new secure API key generate karta hai.
    Return karega: (Asli Key, Hash ki hui Key, UI pe dikhane wala Prefix)
    """
    # 32 bytes ka secure random hex (ekdum bank-level security)
    raw_key = secrets.token_hex(32)
    api_key = f"sk_live_{raw_key}"
    
    # Hash the key (Database mein sirf ye hash jayega)
    hashed_key = hash_api_key(api_key)
    
    # Dashboard par user ko dikhane ke liye first 15 characters
    prefix = api_key[:15] + "..."
    
    return api_key, hashed_key, prefix

def hash_api_key(api_key: str) -> str:
    """
    Asli API key ko SHA-256 use karke encrypt/hash karta hai.
    Is process ko reverse (decrypt) karna impossible hai.
    """
    return hashlib.sha256(api_key.encode()).hexdigest()