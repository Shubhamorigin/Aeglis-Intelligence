import os
from supabase import create_client, Client
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Fetch credentials securely
SB_URL = os.getenv("SB_API_URL")
SB_ANON_KEY = os.getenv("SB_ANON_KEY")
SB_SECRET_KEY = os.getenv("SB_SECRET_KEY")

# Fail fast when required credentials are missing.
if not all([SB_URL, SB_ANON_KEY, SB_SECRET_KEY]):
    raise ValueError("🚨 Supabase Credentials missing! Please check your .env file.")

try:
    
    # Use this client for authentication operations.
    supabase: Client = create_client(SB_URL, SB_ANON_KEY)
    
   
    # Use this client for database operations that require the service key.
    supabase_admin: Client = create_client(SB_URL, SB_SECRET_KEY)
    
    print("✅ Supabase Clients (Auth & Admin) initialized successfully.")

except Exception as e:
    print(f"❌ Failed to initialize Supabase clients: {e}")
    raise e