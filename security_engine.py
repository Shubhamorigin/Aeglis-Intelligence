# Handles API key creation and verification.

import secrets
import hashlib
from fastapi import Security, HTTPException, Header
from fastapi.security.api_key import APIKeyHeader

# Reads the API key from the Authorization header.
api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

def generate_new_api_key():
    """Generate a new API key along with a stored hash and a short display prefix."""
    # Create 32 bytes of cryptographically secure random data.
    raw_key = secrets.token_hex(32)
    api_key = f"sk_live_{raw_key}"

    # Store only a hash in the database.
    hashed_key = hash_api_key(api_key)

    # Show only a short prefix in the dashboard.
    prefix = api_key[:15] + "..."

    return api_key, hashed_key, prefix

def hash_api_key(api_key: str) -> str:
    """Hash an API key with SHA-256 for safe storage and comparison."""
    return hashlib.sha256(api_key.encode()).hexdigest()