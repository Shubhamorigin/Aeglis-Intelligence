import os
import shutil
import json
import time
import secrets
import uvicorn
from fastapi import FastAPI, Request, UploadFile, File, Form, HTTPException, status, Depends, BackgroundTasks, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from fastapi.concurrency import run_in_threadpool
from fastapi.security import APIKeyHeader
from pydantic import BaseModel
from supabase import create_client, Client
from dotenv import load_dotenv

# Using AsyncGroq to prevent blocking the FastAPI event loop during high traffic
from groq import AsyncGroq

# Our specialized analysis engines
from scanner_engine import FalconEngine
from core_engine import falcon_detect_master_scan, save_to_cache

# 🚀 NEW: Enterprise Engines (B2B) - Ensure these files exist in your folder
from security_engine import generate_new_api_key, hash_api_key
from webhook_engine import dispatch_webhook

# 1. INITIALIZATION & CONFIG
load_dotenv()

app = FastAPI(
    title="Falcon Detect API v3", 
    description="The Ultimate Hybrid AI Security Engine (Consumer + Developer B2B)"
)

# Engine Instance
engine = FalconEngine()

# Groq Async AI Client (Performance Boost)
groq_client = AsyncGroq(api_key=os.getenv("GROQ_API_KEY", ""))

# Supabase Database Connection
SB_URL = os.getenv("SB_API_URL")
SB_KEY = os.getenv("SB_ANON_KEY")

supabase: Client = None
if SB_URL and SB_KEY:
    try:
        supabase = create_client(SB_URL, SB_KEY)
        print("✅ Supabase Intelligence Database Connected!")
    except Exception as e:
        print(f"❌ Supabase Connection Failed: {e}")

# 2. MIDDLEWARE (CORS for Frontend Connectivity)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Change this to your domain in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. MODELS & CONSTANTS
class ScanRequest(BaseModel):
    user_id: str
    input_text: str

class DashboardKeyRequest(BaseModel):
    user_id: str

class WebhookUpdateRequest(BaseModel):
    user_id: str
    webhook_url: str

MAX_FILE_SIZE = 50 * 1024 * 1024 # 50 MB safety limit to prevent server overload

# =====================================================================
# 🟢 MODULE 1: ORIGINAL B2C CONSUMER LOGIC (DO NOT MODIFY)
# =====================================================================

async def verify_and_deduct_credit(user_id: str):
    """Check user credits and deduct 1 credit upon successful scanning."""
    if not supabase: return True # Bypass if local testing is active
    
    try:
        # 1. Check credits from user profile
        res = supabase.table("profiles").select("credits").eq("id", user_id).execute()
        
        if not res.data:
            raise HTTPException(status_code=404, detail="User profile not found in database.")
            
        current_credits = res.data[0]["credits"]
        
        # 2. Block scan if credits are 0 or less
        if current_credits <= 0:
            raise HTTPException(
                status_code=402, 
                detail="Your credits have expired. Please upgrade your plan to continue."
            )
            
        # 3. Deduct 1 credit
        new_credits = current_credits - 1
        supabase.table("profiles").update({"credits": new_credits}).eq("id", user_id).execute()
        
        return new_credits
    except HTTPException:
        raise
    except Exception as e:
        print(f"Credit System Error: {e}")
        raise HTTPException(status_code=500, detail="Credit verification failed.")

# 🛡️ CONSUMER ORIGIN GUARD: Sirf tumhari website ko allow karega
async def verify_consumer_origin(request: Request):
    origin = request.headers.get("origin")
    allowed_origins = [
        "https://falcon-detect.in",
        "http://localhost:3000",
        "http://127.0.0.1:5501",
        "https://falcondetect.vercel.app"
    ]
    if origin not in allowed_origins:
        raise HTTPException(
            status_code=403,
            detail="Unauthorized: Consumer API restricted to official Falcon UI."
        )
    return True

async def get_ai_verdict(report_data: dict, context_val: str):
    """
    Perform security analysis using Groq AI (Llama 3.3).
    """
    # Token Optimization: Truncate massive user text to prevent API crashes
    safe_context = context_val[:2000] + "... [TRUNCATED]" if context_val and len(context_val) > 2000 else context_val

    prompt = f"""
    You are Falcon Intelligence, a senior cybersecurity analyst.
    Analyze this combined report and determine the safety.
    
    User Context/Message: "{safe_context}"
    Autopsy Report (File/URL Data):
    {json.dumps(report_data, indent=2)}
    
    Task:
    1. Verdict: SAFE, DANGER, or WARNING.
    2. Explanation: Provide a sharp, concise explanation in English.
    Explain why it is dangerous (permissions, hidden JavaScript, or scam language).
    3. User Advice: What should the user do (Delete, block, or ignore).

    STRICT GUIDELINES:
    1. If 'threat_detected' is false AND no suspicious indicators (URLs, JS, high-risk perms) are found, mark it as SAFE.
    2. Do NOT give a WARNING just because the file hash is unknown (VirusTotal 404). Many personal files are unique and won't be on VirusTotal.
    3. Only use WARNING if there is a specific, logical reason (e.g., hidden metadata in a document or a weird URL in a message).
    4. Use DANGER only if high-risk permissions or confirmed malicious links are present.
    
    Output Format (Strict JSON):
    {{
        "risk_level": "DANGER/SAFE/WARNING",
        "reason": "English explanation here..."
    }}
    """
    try:
        # Await the async Groq call for unblocked server performance
        completion = await groq_client.chat.completions.create(
            messages=[
                {"role": "system", "content": "You are a professional cybersecurity expert responding strictly in English and JSON format."},
                {"role": "user", "content": prompt}
            ],
            model="llama-3.3-70b-versatile",
            response_format={"type": "json_object"}
        )
        return json.loads(completion.choices[0].message.content)
    except Exception as e:
        print(f"⚠️ Groq AI Error: {e}")
        return {
            "risk_level": "WARNING",
            "reason": "AI Analysis failed, but raw indicators are suspicious. Stay cautious!"
        }

# =====================================================================
# 🟣 MODULE 2: NEW B2B ENTERPRISE LOGIC (Developers API)
# =====================================================================

api_key_header = APIKeyHeader(name="Authorization", auto_error=False)

async def verify_developer_key(authorization: str = Depends(api_key_header)):
    """The Security Guard for Developer API Endpoints with Dynamic Plan Limits."""
    if not authorization:
        raise HTTPException(status_code=401, detail="API Key missing. Use 'Bearer sk_live_...'")
    
    token = authorization.replace("Bearer ", "").strip()
    hashed_token = hash_api_key(token)
    
    if not supabase:
        raise HTTPException(status_code=500, detail="Database disconnected")
        
    # 1. API Key verify karo
    res = supabase.table("api_keys").select("user_id, is_active").eq("key_hash", hashed_token).execute()
    
    if not res.data or not res.data[0]["is_active"]:
        raise HTTPException(status_code=401, detail="Invalid or Inactive API Key")
        
    user_id = res.data[0]["user_id"]
    
    # 2. User ki Profile fetch karo (Usage aur Plan dono ke liye)
    prof_res = supabase.table("profiles").select("monthly_api_usage, plan_type").eq("id", user_id).execute()
    
    if prof_res.data:
        profile = prof_res.data[0]
        usage = profile.get("monthly_api_usage", 0)
        # Plan type ko handle karna (default to 'free' agar empty ho)
        plan = (profile.get("plan_type") or "free").lower()

        # 3. Dynamic Limits Mapping
        PLAN_LIMITS = {
            "free": 100,
            "startup": 10000,
            "enterprise": 50000
        }
        
        # Current plan ki limit nikaalo (agar plan list mein nahi hai toh free ki limit laga do)
        limit = PLAN_LIMITS.get(plan, 100)

        # 4. Limit Check logic
        if usage >= limit:
            raise HTTPException(
                status_code=429, 
                detail=f"Quota Exceeded: Your {plan.upper()} plan limit of {limit:,} requests/month is reached. Please upgrade."
            )
            
        # 5. Usage Increment (+1 update)
        supabase.table("profiles").update({"monthly_api_usage": usage + 1}).eq("id", user_id).execute()
        
    return user_id


async def log_api_call(dev_user_id: str, endpoint: str, status_code: int, start_time: float, risk_level: str = None, end_user_id: str = "anonymous"):
    """Records every B2B request into api_logs table for the Dashboard."""
    latency_ms = int((time.time() - start_time) * 1000)
    if supabase:
        supabase.table("api_logs").insert({
            "user_id": dev_user_id,          # Developer ki ID (Zomato)
            "end_user_id": end_user_id,      # 🚀 NAYA: End-user ki ID (Customer)
            "endpoint": endpoint,
            "method": "POST",
            "status_code": status_code,
            "latency_ms": latency_ms,
            "risk_level": risk_level
        }).execute()

async def process_b2b_deep_scan(dev_user_id: str, temp_path: str, filename: str, input_text: str, start_time: float, end_user_id: str):
    """Background task for heavy file processing & webhook dispatch."""
    try:
        file_report = await engine.analyze_file(temp_path)
        combined = {"file_analysis": file_report, "text_message": input_text if input_text else "No message"}
        ai_res = await get_ai_verdict(combined, f"File: {filename}")
        
        # 🚀 Pass end_user_id to logger
        await log_api_call(dev_user_id, "/v3/api/deep-scan", 200, start_time, ai_res["risk_level"], end_user_id)
        
        # Dispatch Webhook
        if supabase:
            prof_res = supabase.table("profiles").select("webhook_url, webhook_secret").eq("id", dev_user_id).execute()
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
        if os.path.exists(temp_path):
            os.remove(temp_path)

# =====================================================================
# 🚀 ROUTERS: DEVELOPER B2B API ENDPOINTS
# =====================================================================

b2b_router = APIRouter(prefix="/v3")

@b2b_router.post("/api/scan")
async def developer_scan(request: ScanRequest, dev_user_id: str = Depends(verify_developer_key)):
    """B2B Endpoint: Fast Text/URL Scan"""
    start_time = time.time()
    try:
        # 🚀 FIX: get_ai_verdict hata diya. Ab seedha master scan ka result use hoga.
        core_result = await run_in_threadpool(falcon_detect_master_scan, request.input_text)
        
        # ai_res ki jagah core_result.get("risk_level") use kiya
        if core_result.get("risk_level") == "DANGER" and core_result.get("type") != "CACHED_RESULT":
            await run_in_threadpool(save_to_cache, request.input_text, "DANGER", "Falcon B2B API Engine")
            
        # 🚀 Pass request.user_id here
        await log_api_call(dev_user_id, "/v3/api/scan", 200, start_time, core_result.get("risk_level"), request.user_id)
        
        # Return me bhi ai_res ki jagah core_result bhej diya
        return {"status": "success", "data": core_result}
    except Exception as e:
        await log_api_call(dev_user_id, "/v3/api/scan", 500, start_time, None, request.user_id)
        raise HTTPException(status_code=500, detail="Developer Scan Failed")
    

@b2b_router.post("/api/deep-scan", status_code=202)
async def developer_deep_scan(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    input_text: str = Form(None),
    user_id: str = Form("anonymous"), # 🚀 NAYA: Form data se user_id catch kar rahe hain
    dev_user_id: str = Depends(verify_developer_key)
):
    """B2B Endpoint: Async File Scan with Webhook Notification"""
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
            
    # 🚀 Pass user_id to background engine
    background_tasks.add_task(process_b2b_deep_scan, dev_user_id, temp_path, file.filename, input_text, start_time, user_id)
    
    return {"status": "processing", "message": "File accepted. Result will be dispatched to your Webhook."}

@b2b_router.post("/dashboard/generate-key")
async def dashboard_generate_key(
    req: DashboardKeyRequest,
    _: bool = Depends(verify_consumer_origin)
):
    """Called by Developer Dashboard UI to roll/create API keys."""
    api_key, hashed_key, prefix = generate_new_api_key()
    if supabase:
        # Disable/delete old keys for this user
        supabase.table("api_keys").delete().eq("user_id", req.user_id).execute()
        # Save new key hash
        supabase.table("api_keys").insert({"user_id": req.user_id, "key_prefix": prefix, "key_hash": hashed_key}).execute()
    return {"status": "success", "api_key": api_key, "prefix": prefix}


@b2b_router.post("/dashboard/webhook")
async def update_webhook_config(
    req: WebhookUpdateRequest,
    _: bool = Depends(verify_consumer_origin)
):
    """
    B2B Dashboard Endpoint: Securely generates a Webhook Secret 
    and saves the Developer's Payload URL to Supabase.
    """
    if not req.webhook_url.startswith("http"):
        raise HTTPException(status_code=400, detail="Invalid URL format. Must start with http:// or https://")
        
    # Generate an Enterprise-Grade Secure Secret (e.g., whsec_a1b2c3...)
    new_secret = f"whsec_{secrets.token_hex(24)}"
    
    try:
        if supabase:
            # Seedha Supabase database me URL aur Secret dono update kar do
            supabase.table("profiles").update({
                "webhook_url": req.webhook_url,
                "webhook_secret": new_secret
            }).eq("id", req.user_id).execute()
            
        return {
            "status": "success", 
            "message": "Webhook configured securely.",
            "webhook_url": req.webhook_url,
            "webhook_secret": new_secret
        }
    except Exception as e:
        print(f"Webhook Config Error: {e}")
        raise HTTPException(status_code=500, detail="Failed to save webhook configuration.")
    


# Include B2B Router into main app
app.include_router(b2b_router)


# =====================================================================
# 👥 ORIGINAL B2C CONSUMER ENDPOINTS (DO NOT MODIFY)
# =====================================================================

@app.get("/")
def health_check():
    return {"status": "Active", "engine": "Falcon Detect Intelligence is Online 🦅"}

@app.post("/scan")
async def scan_text(
    request: ScanRequest,
    _: bool = Depends(verify_consumer_origin)
):
    """
    Basic Text/URL/Hash Scan Endpoint.
    """
    try:
        # Step 0: Check user credits
        await verify_and_deduct_credit(request.user_id)
        
        # Step 1: Run the core Falcon Detect Master Scan (which includes all checks and AI verdict)
        core_result = await run_in_threadpool(falcon_detect_master_scan, request.input_text)

        # Step 2: AUTO-SAVE TO CACHE (If the result is dangerous)
        if core_result.get("risk_level") == "DANGER" and core_result.get("type") != "CACHED_RESULT":
            await run_in_threadpool(save_to_cache, request.input_text, "DANGER", "Falcon AI Text Intelligence")
            
        # Step 3: Save to Database History
        if supabase:
            supabase.table("scans").insert({
                "user_id": request.user_id,
                "input_type": "TEXT/URL",
                "input_data": request.input_text[:250], # Limit history text size
                "risk_level": core_result.get("risk_level"),
                "reason": core_result.get("reason", "Analyzed by Falcon Intelligence")
            }).execute()

        # Step 4: Return core_result directly
        return {"status": "success", "data": core_result}
        
    except HTTPException as e:
        raise e
    except Exception as e:
        print(f"❌ Scan Error: {e}")
        raise HTTPException(status_code=500, detail="Text Scan Engine Failure")

@app.post("/deep-scan")
async def deep_scan(
    user_id: str = Form(...), 
    file: UploadFile = File(...),
    input_text: str = Form(None), # Optional message context
    _: bool = Depends(verify_consumer_origin)
):
    """
    Hybrid Deep File Scan (APK, PDF, Image + Optional Text)
    """
    # Step 0: Check credits first
    await verify_and_deduct_credit(user_id)
    
    if not os.path.exists("temp_uploads"):
        os.makedirs("temp_uploads")
        
    temp_path = f"temp_uploads/{file.filename}"
    
    try:
        # 1. Chunked saving with Strict File Size Limiting
        file_size = 0
        with open(temp_path, "wb") as buffer:
            # Read in chunks to calculate size accurately without consuming memory
            while chunk := await file.read(1024 * 1024): # 1MB chunks
                file_size += len(chunk)
                if file_size > MAX_FILE_SIZE:
                    os.remove(temp_path)
                    raise HTTPException(status_code=413, detail="File too large. Maximum 50MB allowed.")
                buffer.write(chunk)

        # 2. Run FalconEngine Autopsy
        file_report = await engine.analyze_file(temp_path)

        # 3. Combine contexts
        combined_report = {
            "file_analysis": file_report,
            "text_message": input_text if input_text else "No message provided"
        }

        # 4. Get AI Intelligence Verdict
        ai_res = await get_ai_verdict(combined_report, f"File: {file.filename} | Msg: {input_text or ''}")

        # 5. AUTO-SAVE TO CACHE
        if ai_res["risk_level"] == "DANGER" and file_report.get("file_hash"):
            # Check karte hain ki kya ye hash pehle se cache mein tha
            is_already_cached = file_report.get("global_reputation", {}).get("type") == "CACHED_RESULT"
            
            if not is_already_cached:
                await run_in_threadpool(save_to_cache, file_report["file_hash"], "DANGER", "Falcon Deep Engine Autopsy")

        # 6. Save to Database History
        if supabase:
            supabase.table("scans").insert({
                "user_id": user_id,
                "input_type": "HYBRID_FILE_" + file_report.get("mime_type", "UNKNOWN")[:20],
                "input_data": f"File: {file.filename} " + (f"| Msg: {input_text[:100]}" if input_text else ""),
                "risk_level": ai_res["risk_level"],
                "reason": ai_res["reason"],
                "ai_explanation": json.dumps(combined_report) 
            }).execute()

        # 7. Cleanup
        if os.path.exists(temp_path):
            os.remove(temp_path)

        return {
            "status": "success",
            "data": {
                "risk_level": ai_res["risk_level"],
                "reason": ai_res["reason"],
                "input_data": file.filename,
                "raw_report": combined_report
            }
        }

    except HTTPException as e:
        raise e
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        print(f"❌ Deep Scan Error: {e}")
        raise HTTPException(status_code=500, detail="An error occurred during file analysis.")

if __name__ == "__main__":
    # Standard configuration for running locally
    uvicorn.run(app, host="0.0.0.0", port=8000)
