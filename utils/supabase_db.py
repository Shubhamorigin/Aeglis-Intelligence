import os
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Fetch credentials securely
SB_URL = os.getenv("SB_API_URL")
SB_ANON_KEY = os.getenv("SB_ANON_KEY")
SB_SECRET_KEY = os.getenv("SB_SECRET_KEY")

# Fail-safe: Agar .env set nahi hai toh server start hi nahi hoga
if not all([SB_URL, SB_ANON_KEY, SB_SECRET_KEY]):
    raise ValueError("🚨 Supabase Credentials missing! Please check your .env file.")

try:
    
    # Use this ONLY for: supabase_auth.auth.sign_up() or .sign_in_with_password()
    supabase: Client = create_client(SB_URL, SB_ANON_KEY)
    
   
    # Use this for: Database CRUD (scans, profiles, credits). Bypasses RLS!
    supabase_admin: Client = create_client(SB_URL, SB_SECRET_KEY)
    
    print("✅ Supabase Clients (Auth & Admin) initialized successfully.")

except Exception as e:
    print(f"❌ Failed to initialize Supabase clients: {e}")
    raise e