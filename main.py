import asyncio
import os
import sys
import requests
import httpx
# Windows + Playwright/asyncio event-loop compatibility
if sys.platform == "win32":
    try:
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        pass

import json
import time
import secrets
import uvicorn

from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException, Depends, BackgroundTasks, APIRouter, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.concurrency import run_in_threadpool
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, EmailStr
from utils.supabase_db import supabase, supabase_admin
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from dotenv import load_dotenv

# Using AsyncGroq to prevent blocking the FastAPI event loop during high traffic
from groq import AsyncGroq

# Our specialized analysis engines
from scanner_engine import AeglisEngine
from core_engine import Aeglis_master_scan
from security_engine import generate_new_api_key, hash_api_key
from webhook_engine import dispatch_webhook

# =====================================================================
# 1. INITIALIZATION & CONFIG
# =====================================================================
load_dotenv()

app = FastAPI(
    title="Aeglis API v3",
    description="The Ultimate Hybrid AI Security Engine (Consumer + Developer B2B)",
)


# Rate Limiter Setup (DDoS Protection)
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Engine Instance & AI Client
engine = AeglisEngine()
groq_client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY", ""))

# Middleware (CORS)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Production mein ise ["https://Aeglis-detect.in"] kar dena
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_FILE_SIZE = 50 * 1024 * 1024 # 50 MB safety limit

# =====================================================================
# 2. PYDANTIC MODELS (Strictly Secured)
# =====================================================================

class TextScanPayload(BaseModel):
    input_text: str
    lang: str = "en"
    # 🚨 SECURITY FIX: Frontend se user_id accept karna band kar diya hai.
    # Ab system sirf JWT token ko trust karega user_id nikalne ke liye.

class B2BScanRequest(BaseModel):
    input_text: str
    end_user_id: str = "anonymous" # Optional: For B2B Devs to track their customers

class WebhookUpdateRequest(BaseModel):
    webhook_url: str
    # 🚨 IDOR FIX: Removed user_id.

class DashboardKeyRequest(BaseModel):
    pass # Empty body for key generation (user_id JWT se aayegi)

class SignupPayload(BaseModel):
    email: EmailStr
    password: str
    name: str
    fingerprint: str

class LoginPayload(BaseModel):
    email: EmailStr
    password: str

class SupportTicketPayload(BaseModel):
    name: str
    email: EmailStr
    message: str

class DeleteHistoryPayload(BaseModel):
    scan_id: int

class GoogleAuthPayload(BaseModel):
    target_url: str = "https://www.aeglis.com/app.html" # Default Consumer App

class NativeGoogleAuth(BaseModel):
    google_token: str


# =====================================================================
# 3. CORE DEPENDENCIES (Security Guards)
# =====================================================================

async def get_current_user(request: Request) -> str:
    """Extracts and verifies JWT Token OR Device Key to return secure user_id (Hybrid Guard)"""
    auth = request.headers.get("Authorization")
    
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header")
        
    token = auth[7:]
    
    try:
        # Only normal JWT will be accepted.
        user = supabase.auth.get_user(token)
        if not user.user:
            raise HTTPException(status_code=401, detail="Invalid JWT token")
        return user.user.id
            
            
    except Exception as e:
        # Backend terminal mein print karna zaroori hai debugging ke liye
        print(f"Auth Blocked: {str(e)}") 
        raise HTTPException(status_code=401, detail="Token verification failed")

async def verify_user_has_credits(current_user_id: str) -> None:
    """Checks credits existence for B2C, BUT does not deduct.

    Deduction is done at the end of a successful scan flow.
    """
    if not supabase:
        return  # local testing bypass

    try:
        res = supabase_admin.table("profiles").select("app_credits").eq("id", current_user_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="User profile not found in database.")

        current_credits = res.data[0].get("app_credits", 0)
        if current_credits <= 0:
            raise HTTPException(status_code=402, detail="Credits expired. Please upgrade your plan.")
    except HTTPException:
        raise
    except Exception as e:
        print(f"Credit System Error (verify_user_has_credits): {e}")
        raise HTTPException(status_code=500, detail="Credit verification failed.")


async def deduct_user_credit(current_user_id: str) -> None:
    """Deduct 1 credit after full successful processing (B2C only)."""
    if not supabase:
        return

    try:
        res = supabase_admin.table("profiles").select("app_credits").eq("id", current_user_id).execute()
        if not res.data:
            raise HTTPException(status_code=404, detail="User profile not found in database.")

        current_credits = res.data[0].get("app_credits", 0)
        if current_credits <= 0:
            raise HTTPException(status_code=402, detail="Credits expired. Please upgrade your plan.")

        supabase_admin.table("profiles").update({"app_credits": current_credits - 1}).eq("id", current_user_id).execute()
    except HTTPException:
        raise
    except Exception as e:
        print(f"Credit System Error (deduct_user_credit): {e}")
        raise HTTPException(status_code=500, detail="Credit deduction failed.")
    except HTTPException:
        raise
    except Exception as e:
        print(f"Credit System Error: {e}")
        raise HTTPException(status_code=500, detail="Credit verification failed.")

async def verify_consumer_origin(request: Request):
    """Guards against direct API abuse via fake clients"""
    origin = request.headers.get("origin")
    allowed_origins = [
        "https://www.aeglis.com",
        "https://developer.aeglis.com",
        "http://localhost:3000",
        "http://127.0.0.1:5501",
        "http://localhost:5502",
        "http://127.0.0.1:5502"
    ]
    # Chrome Extension requests allow karo
    if origin and origin.startswith("chrome-extension://"):
        return True
        
    if origin not in allowed_origins:
        raise HTTPException(status_code=403, detail="Unauthorized: Restricted to official Aeglis UI.")
    return True

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

async def verify_developer_key(authorization: str = Depends(api_key_header)) -> str:
    """B2B Security Guard: Extracts Developer ID from API Key and checks Limits"""
    if not authorization:
        raise HTTPException(status_code=401, detail="API Key missing. Use 'Bearer sk_live_...'")
    
    token = authorization.replace("Bearer ", "").strip()
    hashed_token = hash_api_key(token)
    
    if not supabase: raise HTTPException(status_code=500, detail="Database disconnected")
        
    # Verify API Key
    res = supabase_admin.table("api_keys").select("user_id, is_active").eq("key_hash", hashed_token).execute()
    if not res.data or not res.data[0]["is_active"]:
        raise HTTPException(status_code=401, detail="Invalid or Inactive API Key")
        
    dev_user_id = res.data[0]["user_id"]
    
    # Check Plan Limits
    prof_res = supabase_admin.table("profiles").select("monthly_api_usage, api_plan").eq("id", dev_user_id).execute()
    if prof_res.data:
        profile = prof_res.data[0]
        usage = profile.get("monthly_api_usage", 0)
        plan = (profile.get("api_plan") or "free").lower()

        PLAN_LIMITS = {"free": 100, "startup": 10000, "enterprise": 50000}
        limit = PLAN_LIMITS.get(plan, 100)

        if usage >= limit:
            raise HTTPException(status_code=429, detail=f"Quota Exceeded: {plan.upper()} limit of {limit:,} requests reached.")
            
        supabase_admin.table("profiles").update({"monthly_api_usage": usage + 1}).eq("id", dev_user_id).execute()
        
    return dev_user_id

# =====================================================================
# 4. HELPER FUNCTIONS
# =====================================================================

async def get_ai_verdict(report_data: dict, context_val: str, lang: str = "en"):
    """Groq Llama 3.3 Intelligence Analysis"""
    
    # 🚀 1. The Smart Language Mapper (Short code to Full Name)
    language_map = {
        "en": "English",
        "hi": "Hindi",
        "es": "Spanish",
        "pt": "Portuguese",
        "in": "Indonesian",
        "ar": "Arabic"
    }
    target_language = language_map.get(lang, "English") # Default English rahega
    
    safe_context = context_val[:2000] + "... [TRUNCATED]" if context_val and len(context_val) > 2000 else context_val
    
    # 🚀 2. Prompt mein target_language inject kar diya
    prompt = f"""
    You are Aeglis Intelligence, a senior cybersecurity analyst.
    Analyze this combined report and determine the safety.
    
    User Context/Message: "{safe_context}"
    Autopsy Report: {json.dumps(report_data, indent=2)}
    
    Task:
    1. Assess the risk level (SAFE, DANGER, or WARNING).
    2. Write a single response that combines a sharp, concise explanation WITH the final advice on what the user should do.

    STRICT GUIDELINES:
    1. If 'threat_detected' is false AND no suspicious indicators are found, mark SAFE.
    2. Do NOT give WARNING just because file hash is unknown.
    3. Output strictly in JSON format with EXACTLY two keys, no more, no less: 
    {{"risk_level": "...", "reason": "..."}}
    4. CRITICAL TRANSLATION: You MUST write the "reason" field strictly in {target_language}. Do not output the reason in any other language.
    
    Ensure your combined explanation and advice goes 40 words entirely into the "reason" key.
    """
    try:
        completion = await groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a professional cybersecurity expert responding strictly in JSON."},
                {"role": "user", "content": prompt}
            ],
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"}
        )
        return json.loads(completion.choices[0].message.content)
    except Exception as e:
        print(f"⚠️ Groq AI Error: {e}")
        return {"risk_level": "WARNING", "reason": "AI Analysis failed, but indicators look suspicious."}

    
async def log_api_call(dev_user_id: str, endpoint: str, status_code: int, start_time: float, risk_level: str = None, end_user_id: str = "anonymous"):
    """Records B2B request into api_logs"""
    latency_ms = int((time.time() - start_time) * 1000)
    if supabase:
        supabase_admin.table("api_logs").insert({
            "user_id": dev_user_id,
            "end_user_id": end_user_id,
            "endpoint": endpoint,
            "method": "POST",
            "status_code": status_code,
            "latency_ms": latency_ms,
            "risk_level": risk_level
        }).execute()

async def process_b2b_deep_scan(dev_user_id: str, temp_path: str, filename: str, input_text: str, start_time: float, end_user_id: str):
    """Background task for heavy file processing & webhook dispatch"""
    try:
        file_report = await engine.analyze_file(temp_path)
        combined = {"file_analysis": file_report, "text_message": input_text if input_text else "No message"}
        ai_res = await get_ai_verdict(combined, f"File: {filename}")
        
        await log_api_call(dev_user_id, "/v3/api/deep-scan", 200, start_time, ai_res["risk_level"], end_user_id)
        
        if supabase:
            prof_res = supabase_admin.table("profiles").select("webhook_url, webhook_secret").eq("id", dev_user_id).execute()
            if prof_res.data:
                w_url = prof_res.data[0].get("webhook_url")
                w_sec = prof_res.data[0].get("webhook_secret")
                if w_url and w_sec:
                    scan_data = {"risk_level": ai_res["risk_level"], "reason": ai_res["reason"], "file": filename, "user_id": end_user_id}
                    await dispatch_webhook(w_url, w_sec, "scan.completed", scan_data)
                    
    except Exception as e:
        print(f"Background B2B Error: {e}")
        await log_api_call(dev_user_id, "/v3/api/deep-scan", 500, start_time, None, end_user_id)
    finally:
        if os.path.exists(temp_path): os.remove(temp_path)


# =====================================================================
# 5. AUTHENTICATION (B2C & Developer Signup)
# =====================================================================

@app.post("/auth/signup")
async def signup(payload: SignupPayload):
    try:
        auth_response = supabase.auth.sign_up({
            "email": payload.email, "password": payload.password,
            "options": {"data": {"full_name": payload.name, "browser_fingerprint": payload.fingerprint}}
        })
        if not auth_response.session:
             return {"status": "pending", "message": "Account created! Please verify your email."}
        return {"status": "success", "access_token": auth_response.session.access_token, "message": "Account created successfully!"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/auth/login")
async def login(payload: LoginPayload):
    try:
        auth_response = supabase.auth.sign_in_with_password({"email": payload.email, "password": payload.password})
        if not auth_response.session:
            raise HTTPException(status_code=401, detail="Invalid email or password.")
        return {"status": "success", "access_token": auth_response.session.access_token, "message": "Login successful"}
    except Exception as e:
        raise HTTPException(status_code=401, detail="Invalid credentials.")
    
@app.post("/auth/google")
async def google_auth_login(payload: GoogleAuthPayload = None):
    try:
        # Frontend jo URL bhejega (Dev ya Consumer), usko yahan pakdenge
        target = payload.target_url if payload else "https://www.aeglis.com/app.html"
        
        # SMART TRICK: Supabase/Google ko bol rahe hain ki callback ke time 
        # ye 'target_url' wapas humein bhej dena
        backend_callback = f"https://api.aeglis.com/auth/callback?target_url={target}"
        
        res = supabase.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {"redirect_to": backend_callback}
        })
        return {"url": res.url}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Google Auth initialization failed")
    
@app.get("/auth/callback")
async def google_auth_callback(request: Request, code: str, target_url: str = "https://www.aeglis.com/app.html"):
    try:
        auth_response = supabase.auth.exchange_code_for_session({"auth_code": code})
        token = auth_response.session.access_token
        
        # 🚀 TRUE SSO FIX: Hamesha pehle central Auth (5501) par bhejo token ke sath
        central_auth = "https://www.aeglis.com/auth.html"
        
        # User central auth pe aayega, wahan JS usko save karega, aur target_url pe bhej dega
        return RedirectResponse(url=f"{central_auth}?token={token}&redirect_to={target_url}")
    except Exception as e:
        # Agar error aaya to fallback main login page par
        return RedirectResponse(url="https://www.aeglis.com/auth.html?error=auth_failed")

@app.post("/auth/native-google")
async def native_google_login(payload: NativeGoogleAuth):
    """B2C Endpoint: For Android Native Google Sign-In via Supabase"""
    try:
        # 🚀 Supabase ka apna Native Magic
        # Ye Google Token ko verify karega aur user ko DB mein login/signup kar dega
        auth_response = supabase.auth.sign_in_with_id_token({
            "provider": "google",
            "token": payload.google_token
        })
        
        if not auth_response.session:
            raise HTTPException(status_code=401, detail="Google Auth failed at Supabase")
            
        # Supabase ne apna JWT (access_token) de diya hai!
        return {
            "status": "success", 
            "access_token": auth_response.session.access_token,
            "message": "Intelligence Engine Authenticated via Supabase"
        }
        
    except Exception as e:
        print(f"🚨 Native Auth Error: {e}")
        raise HTTPException(status_code=401, detail=f"Authentication failed: {str(e)}")




@app.post("/profile/me") 
async def get_my_profile(
    request: Request, 
    user_id: str = Depends(get_current_user),
    x_client_type: str = Header(default="b2c")  # 🔥 Header se frontend ka type pakda
):
    try:
        for attempt in range(3):
            # 🛠️ Step 1: Database se saara raw data utha lo (Naye columns ke sath)
            columns = 'id, full_name, email, app_credits, app_plan, api_plan, webhook_url, webhook_secret, monthly_api_usage'
            user_res = supabase_admin.table('profiles').select(columns).eq('id', user_id).execute()
            
            if user_res.data:
                raw_data = user_res.data[0]
                
                # 🎨 Step 2: Base Profile (Jo dono dashboards ko chahiye)
                filtered_profile = {
                    "id": raw_data["id"],
                    "full_name": raw_data["full_name"],
                    "email": raw_data["email"]
                }
                
                # 🏢 Step 3: B2B Logic (Dev Dashboard)
                if x_client_type == "b2b":
                    filtered_profile["plan_type"] = raw_data.get("api_plan", "free")
                    filtered_profile["monthly_api_usage"] = raw_data.get("monthly_api_usage", 0)
                    filtered_profile["webhook_url"] = raw_data.get("webhook_url")
                    filtered_profile["webhook_secret"] = raw_data.get("webhook_secret")
                    # Notice: Yahan humne 'credit' dictionary mein add hi nahi kiya!
                    
                # 📱 Step 4: B2C Logic (Aeglis Mobile App)
                else:
                    filtered_profile["plan_type"] = raw_data.get("app_plan", "free")
                    filtered_profile["credits"] = raw_data.get("app_credits", 0)
                    # Notice: Yahan webhooks aur API usage skip kar diya taaki app light rahe!

                # Final clean response return karo
                return {"status": "success", "profile": filtered_profile}
                
            await asyncio.sleep(0.5)
            
        return JSONResponse(status_code=404, content={"detail": "Profile not found. Please try again later."})
        
    except Exception as e:
        print(f"Error: {e}") # Debugging ke liye console me print kar lena
        return JSONResponse(status_code=500, content={"detail": "Database connection error"})
        
        

# =====================================================================
# 6. DEVELOPER B2B API & DASHBOARD ENDPOINTS
# =====================================================================

b2b_router = APIRouter(prefix="/v3")

@b2b_router.post("/api/scan")
async def developer_scan(request: Request, payload: B2BScanRequest, dev_user_id: str = Depends(verify_developer_key)):
    """B2B Endpoint: Secured by API Key"""
    start_time = time.time()
    try:
        core_result = await Aeglis_master_scan(payload.input_text)
            
        await log_api_call(dev_user_id, "/v3/api/scan", 200, start_time, core_result.get("risk_level"), payload.end_user_id)
        return {"status": "success", "data": core_result}
    except Exception as e:
        await log_api_call(dev_user_id, "/v3/api/scan", 500, start_time, None, payload.end_user_id)
        raise HTTPException(status_code=500, detail="Developer Scan Failed")

@b2b_router.post("/api/deep-scan", status_code=202)
async def developer_deep_scan(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    input_text: str = Form(None),
    end_user_id: str = Form("anonymous"), # For B2B tracking
    dev_user_id: str = Depends(verify_developer_key)
):
    """B2B Deep Scan: Secured by API Key"""
    start_time = time.time()
    if not os.path.exists("temp_uploads"): os.makedirs("temp_uploads")
    
    temp_path = f"temp_uploads/b2b_{secrets.token_hex(8)}_{file.filename}"
    file_size = 0
    with open(temp_path, "wb") as buffer:
        while chunk := await file.read(1024 * 1024):
            file_size += len(chunk)
            if file_size > MAX_FILE_SIZE:
                os.remove(temp_path)
                raise HTTPException(status_code=413, detail="File too large. Maximum 50MB allowed.")
            buffer.write(chunk)
            
    background_tasks.add_task(process_b2b_deep_scan, dev_user_id, temp_path, file.filename, input_text, start_time, end_user_id)
    return {"status": "processing", "message": "File accepted. Result will be dispatched to your Webhook."}

# ---> DASHBOARD ENDPOINTS (Secured by JWT Token for Frontend Access) <---
@b2b_router.post("/dashboard/generate-key")
async def dashboard_generate_key(
    request: Request,
    payload: DashboardKeyRequest,
    current_user_id: str = Depends(get_current_user),
    _: bool = Depends(verify_consumer_origin)
):
    api_key, hashed_key, prefix = generate_new_api_key()
    if supabase:
        supabase_admin.table("api_keys").delete().eq("user_id", current_user_id).execute()
        supabase_admin.table("api_keys").insert({"user_id": current_user_id, "key_prefix": prefix, "key_hash": hashed_key}).execute()
    return {"status": "success", "api_key": api_key, "prefix": prefix}

@b2b_router.post("/dashboard/webhook")
async def update_webhook_config(
    request: Request,
    payload: WebhookUpdateRequest,
    current_user_id: str = Depends(get_current_user),
    _: bool = Depends(verify_consumer_origin)
):
    if not payload.webhook_url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL format.")
    new_secret = f"whsec_{secrets.token_hex(24)}"
    try:
        if supabase:
            supabase_admin.table("profiles").update({"webhook_url": payload.webhook_url, "webhook_secret": new_secret}).eq("id", current_user_id).execute()
        return {"status": "success", "message": "Webhook configured.", "webhook_url": payload.webhook_url, "webhook_secret": new_secret}
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to save webhook configuration.")
    
@b2b_router.get("/dashboard/api-logs")
async def get_api_logs(request: Request, current_user_id: str = Depends(get_current_user)):
    try:
        logs_res = supabase_admin.table("api_logs").select("*").eq("user_id", current_user_id).order("created_at", desc=True).execute()
        return {"status": "success", "logs": logs_res.data}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch API logs.")
    
@b2b_router.get("/dashboard/api-data")
async def get_api_data(request: Request, current_user_id: str = Depends(get_current_user)):
    try:
        data_res = supabase_admin.table("api_keys").select("key_prefix, created_at").eq("user_id", current_user_id).order("created_at", desc=True).execute()
        return {"status": "success", "data": data_res.data}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to fetch API data.")

app.include_router(b2b_router)


# =====================================================================
# 7. CONSUMER B2C ENDPOINTS (Protected by Rate Limits & JWT Auth)
# =====================================================================

@app.get("/")
def health_check():
    return {"status": "Active", "engine": "Aeglis Intelligence is Online 🦅"}

@app.post("/scan")
@limiter.limit("10/minute")
async def scan_text(
    request: Request, # FIX: SlowAPI needs request object first
    payload: TextScanPayload,
    current_user_id: str = Depends(get_current_user),
    _: bool = Depends(verify_consumer_origin)
):
    try:
        await verify_user_has_credits(current_user_id)
        # 🚀 FIX: payload.lang ko Aeglis_master_scan mein bhej diya
        core_result = await Aeglis_master_scan(payload.input_text, payload.lang)
            
        if supabase:
            supabase_admin.table("scans").insert({
                "user_id": current_user_id,
                "input_type": core_result.get('type', 'TEXT'), # FIX: type field ko safely access karna
                "input_data": payload.input_text[:250],
                "risk_level": core_result.get("risk_level"),
                "reason": core_result.get("reason", "Analyzed by Aeglis Intelligence")
            }).execute()

        # ---- B2C Credit Deduction (after scan complete; fail-safe) ----
        free_scan_types = ["AEGLIS_WHITELIST"]
        scan_type = core_result.get("type")
        if scan_type not in free_scan_types:   
            # Deduct only when we are sure scan result is produced.
            await deduct_user_credit(current_user_id)




        return {"status": "success", "data": core_result}


    except HTTPException as e:
        raise e
    except Exception as e:
        # Log real error so we can identify the crash source (scan engine vs DB insert vs other)
        print(f"❌ /scan runtime error: {repr(e)}")
        raise HTTPException(status_code=500, detail="Text Scan Engine Failure")

    
class InterceptScanPayload(BaseModel):
    url: str
    filename: str | None = None
    lang: str = "en"


@app.post("/scan/intercept")
@limiter.limit("5/minute")
async def scan_intercept(
    request: Request,
    payload: InterceptScanPayload,
    current_user_id: str = Depends(get_current_user),
    _: bool = Depends(verify_consumer_origin)
):
    """B2C Endpoint: Extension intercept downloads URL and asks backend to scan."""
    
    await verify_user_has_credits(current_user_id)

    if not payload.url or not payload.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid url")

    os.makedirs("temp_uploads", exist_ok=True) # Cleaner way to create dir

    original_name = (payload.filename or "intercept_file").replace("/", "_").replace("\\", "_")
    temp_path = f"temp_uploads/intercept_{secrets.token_hex(8)}_{original_name}"

    total_read = 0
    max_bytes = 50 * 1024 * 1024 # 50MB in bytes

    try:
        # Use httpx.AsyncClient to prevent event loop blocking
        async with httpx.AsyncClient(verify=False) as client:
            async with client.stream("GET", payload.url, timeout=15.0) as response:
                
                # 1. Handle Private/Unauthorized Files
                if response.status_code in (401, 403):
                    msg = (
                        "Aeglis Alert: Private file detected. We cannot scan this automatically. "
                        "Please upload it manually to the Web Dashboard if suspicious."
                    )
                    raise HTTPException(status_code=403, detail=msg)

                # 2. Handle Other HTTP Errors
                if response.status_code != 200:
                    raise HTTPException(status_code=502, detail=f"Failed to fetch file. Status: {response.status_code}")

                # 3. Stream and Save Chunk by Chunk
                with open(temp_path, "wb") as f:
                    async for chunk in response.aiter_bytes(chunk_size=1024 * 1024):
                        total_read += len(chunk)
                        if total_read > max_bytes:
                            raise HTTPException(status_code=413, detail="File too large. Maximum 50MB allowed.")
                        f.write(chunk)

        # 4. Scan saved file locally
        file_report = await engine.analyze_file(temp_path, lang=payload.lang)

        # 5. Credit deduction after success
        await deduct_user_credit(current_user_id)

        return {"status": "success", "data": file_report}

    except HTTPException:
        raise # Re-raise HTTP exceptions so FastAPI handles them

    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Scan intercept failed: {str(e)}")

    finally:
        # 🧹 The Ultimate Cleanup: This block runs NO MATTER WHAT (success or fail)
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as cleanup_err:
                print(f"Failed to clean up temp file {temp_path}: {cleanup_err}")


@app.post("/deep-scan")
@limiter.limit("5/minute")
async def deep_scan(
    request: Request,
    file: UploadFile = File(...),
    input_text: str = Form(None),
    lang: str = Form("en"),
    current_user_id: str = Depends(get_current_user),
    _: bool = Depends(verify_consumer_origin)
):
    if not os.path.exists("temp_uploads"): os.makedirs("temp_uploads")
    temp_path = f"temp_uploads/{file.filename}"
    
    try:
        await verify_user_has_credits(current_user_id)
        file_size = 0
        with open(temp_path, "wb") as buffer:
            while chunk := await file.read(1024 * 1024):
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    os.remove(temp_path)
                    raise HTTPException(status_code=413, detail="File too large. Maximum 50MB allowed.")
                buffer.write(chunk)

        # 1. Run AeglisEngine Autopsy
        file_report = await engine.analyze_file(temp_path)
        
        # 2. Combine contexts
        combined_report = {
            "file_analysis": file_report,
            "text_message": input_text if input_text else "No message provided"
        }

        # 3. Get AI Intelligence Verdict
        # 🚀 FIX: lang variable ko get_ai_verdict function mein bhej diya
        ai_res = await get_ai_verdict(combined_report, f"File: {file.filename} | Msg: {input_text or ''}", lang)
        print(f"🧠 Raw Groq Output: {ai_res}")
        
        # 🛡️ FIX 1: Safe dictionary .get() to prevent KeyErrors if Groq hallucinates
        risk_level = ai_res.get("risk_level", "WARNING")
        reason = ai_res.get("reason", "Analyzed by Aeglis Intelligence")

        # 5. Save to Database History
        if supabase:
            try:
                # 🛡️ FIX 2: Protect against NoneType slicing if mime_type is missing
                mime_raw = file_report.get("mime_type")
                mime_str = str(mime_raw) if mime_raw else "UNKNOWN"
                mime_prefix = mime_str[:20]

                supabase_admin.table("scans").insert({
                    "user_id": current_user_id,
                    "input_type": f"HYBRID_FILE_{mime_prefix}",
                    "input_data": f"File: {file.filename} " + (f"| Msg: {input_text[:100]}" if input_text else ""),
                    "risk_level": risk_level,
                    "reason": reason,
                    "ai_explanation": json.dumps(ai_res) if ai_res else None
                    # Agar reason hi missing hua toh pura ai_res hi DB me save ho jayega, jo ki better hai than crashing the DB insert. (Ye field optional hona chahiye DB me) 
                    # 🛡️ FIX 3: Removed "ai_explanation" field to prevent DB crashes if column doesn't exist
                }).execute()
            except Exception as db_err:
                print(f"⚠️ History Save Error (Ignored): {db_err}")
                # Agar DB fat bhi gaya, tab bhi user ko result dikhega!

        if os.path.exists(temp_path): os.remove(temp_path)
        
        await deduct_user_credit(current_user_id)

        return {
            "status": "success",
            "data": {
                "risk_level": risk_level,
                "reason": reason,
                "input_data": file.filename,
                "raw_report": combined_report
            }
        }

    except HTTPException as e: raise e
    except Exception as e:
        if os.path.exists(temp_path): os.remove(temp_path)
        print(f"❌ Deep Scan Error: {str(e)}")
        # Ab terminal/log me exact error string print hogi
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
        
@app.post("/get/history")
async def get_history(request: Request, current_user_id: str = Depends(get_current_user)):
    
    # 🚀 FIX: .eq('is_deleted', False) add kar diya hai
    scan_res = supabase_admin.table('scans')\
        .select('id, input_data, risk_level, scanned_at, reason')\
        .eq('user_id', current_user_id)\
        .eq('is_deleted', False)\
        .execute()
        
    if scan_res.data:
        return {"status": "success", "history": scan_res.data}
    return {"status": "success", "history": []}
    
@app.post("/delete/history")
async def delete_history(
    request: Request,
    current_user_id: str = Depends(get_current_user)
):
    try:
        data = await request.json()
        scan_id = data.get("scan_id")
        
        if scan_id is None:
            raise ValueError("scan_id is missing or null from frontend!")
            
        # Bina int() convert kiye direct pass kar do, Supabase dono (UUID/Int) samajhta hai
        supabase_admin.table('scans').update({"is_deleted": True}).eq('id', scan_id).eq('user_id', current_user_id).execute()
        
        return {"status": "success", "message": "Scan history entry deleted."}
    except Exception as e:
        print(f"❌ Delete Error: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/delete/all-history")
async def delete_all_history(
    request: Request,
    current_user_id: str = Depends(get_current_user)
):
    try:
        # Seedha user ki token ID se uski saari history soft-delete ho jayegi
        supabase_admin.table('scans').update({"is_deleted": True}).eq('user_id', current_user_id).execute()
        return {"status": "success", "message": "All scan history entries deleted."}
    except Exception as e:
        print(f"Delete All Error: {e}")
        raise HTTPException(status_code=500, detail="Server Error.")


@app.post("/support/ticket", tags=["Support"])
@limiter.limit("3/minute")  # Spam protection: Ek IP se 1 minute mein max 3 ticket
async def create_support_ticket(
    request: Request, # SlowAPI rate limiter ke liye zaroori hai
    payload: SupportTicketPayload,
    _: bool = Depends(verify_consumer_origin) # Sirf Aeglis website se aayega, Postman se nahi (NO JWT NEEDED)
):
    """Public Endpoint: Anyone can submit a support ticket without logging in."""
    try:
        if supabase:
            # supabase_admin (Service Key) use kar rahe hain taaki bina RLS/Login ke data insert ho sake
            supabase_admin.table("support_tickets").insert({
                "name": payload.name,
                "email": payload.email,
                "message": payload.message
            }).execute()
            
        return {
            "status": "success", 
            "message": "Your support ticket has been submitted successfully. We will reach out to you shortly."
        }
        
    except Exception as e:
        print(f"🚨 Support Ticket Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to submit ticket. Please try again later.")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
