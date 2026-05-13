import os
import asyncio
import logging
import base64
import concurrent.futures
import sys
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("httpx")
logger.setLevel(logging.WARNING)

async def detonate_url(target_url: str) -> dict:
    """
    Super-fast headless execution. Skips screenshots and extracts pure visible text 
    for the AI Context Engine in under 4 seconds.
    """
    logger.info(f"Aeglis Dynamic Sandbox executing: {target_url}")
    
    network_domains = set()
    scan_result = {
        "target_url": target_url,
        "status": "failed",
        "error_message": None,
        "network_traffic": [],
        "extracted_text": None
    }

    async with async_playwright() as p:
        try:
            # Launch Chromium optimized for speed
            # NOTE: Add `--single-process` to reduce Windows subprocess/transport issues.
            browser = await p.chromium.launch(
                headless=True,
                args=[
                    "--no-sandbox",
                    "--disable-setuid-sandbox",
                    "--disable-dev-shm-usage",
                ]
            )

            
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ignore_https_errors=True
            )
            
            page = await context.new_page()
            page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))

            # --- JS/behavior signals (visual-only HTML won't show these) ---
            js_alerts = {
                "clipboard_write_detected": False,
                "suspicious_redirect": False,
                "keylogger_like_behavior": False,
                "crypto_mining_like_behavior": False,
                "form_data_exfil_like_behavior": False,
            }

            async def mark_true(key: str):
                js_alerts[key] = True

            # Periodically sync JS markers set by our init scripts
            async def sync_markers():
                try:
                    val = await page.evaluate("() => window.__AeglisClipboardWrite === true")
                    if val:
                        js_alerts["clipboard_write_detected"] = True
                except Exception:
                    pass

            # Clipboard hijack
            await page.add_init_script(
                """
                () => {
                  const origWriteText = navigator.clipboard && navigator.clipboard.writeText;
                  if (origWriteText) {
                    navigator.clipboard.writeText = function(...args) {
                      window.__AeglisClipboardWrite = true;
                      return origWriteText.apply(this, args);
                    };
                  }
                }
                """
            )

            # Listen for redirects (main-frame only to avoid iframe/resource false positives)
            async def handle_navigation(frame):
                try:
                    if frame != page.main_frame:
                        return
                    current = frame.url if frame else None
                    if current and current != target_url and not current.startswith("about:"):
                        final_urls.append(current)
                        # 2+ alag URLs = actual redirect (dedupe)
                        if len(set(final_urls)) >= 2:
                            js_alerts["suspicious_redirect"] = True
                except Exception:
                    pass

            page.on("framenavigated", lambda frame: asyncio.create_task(handle_navigation(frame)))


            # Network monitoring for exfil-like requests and mining endpoints
            async def handle_request(request):
                try:
                    if request.method in ["POST", "PUT"] or any(h in request.url.lower() for h in ["login", "auth", "password", "wallet", "seed", "mnemonic", "keystore"]):
                        if any(x in request.url.lower() for x in ["collect", "exfil", "steal", "bot", "miner", "mine", "stratum"]):
                            js_alerts["form_data_exfil_like_behavior"] = True
                    if any(x in request.url.lower() for x in ["miner", "mining", "stratum", "hashrate"]):
                        js_alerts["crypto_mining_like_behavior"] = True
                except Exception:
                    pass

            page.on("request", lambda req: asyncio.create_task(handle_request(req)))

            # Keylogger-like detection: detect keydown handlers via evaluate scan (best-effort)
            async def probe_keylogger():
                try:
                    result = await page.evaluate("""
                        () => {
                          const events = (window.getEventListeners && window.getEventListeners(window)) || null;
                          return !!events;
                        }
                    """)
                    if result:
                        js_alerts["keylogger_like_behavior"] = True
                except Exception:
                    pass

            page.on("domcontentloaded", lambda: asyncio.create_task(probe_keylogger()))


            # Track unique domains contacted in background
            final_urls = []

            async def handle_response(response):
                try:
                    domain = response.url.split('/')[2]
                    network_domains.add(domain)
                except:
                    pass

            page.on("response", handle_response)

            # Track redirect chain URLs (including final)
            async def capture_final_url():
                try:
                    final_urls.append(page.url)
                except:
                    pass

            page.on("load", lambda _: asyncio.create_task(capture_final_url()))


            logger.info("Loading DOM...")
            await page.goto(target_url, wait_until="domcontentloaded", timeout=10000)
            
            # Wait only 1.5 seconds for delayed text to render
            await page.wait_for_timeout(1500)
            
            raw_html = await page.content()
            
            # Take screenshot for visual-only phishing detection
            screenshot_bytes = await page.screenshot(type="jpeg", quality=60, full_page=True)
            scan_result["screenshot_base64"] = base64.b64encode(screenshot_bytes).decode("utf-8")
            
            # Redirect chain evidence for short-link scams
            scan_result["redirect_chain"] = final_urls[-10:]

            # Extract pure visible text for Groq Llama
            soup = BeautifulSoup(raw_html, 'html.parser')
            for script in soup(["script", "style", "noscript", "meta"]):
                script.extract()
            
            extracted_text = soup.get_text(separator=' ', strip=True)
            
            scan_result["extracted_text"] = extracted_text[:6000] # Limit to 6000 chars for token safety
            scan_result["network_traffic"] = list(network_domains)[:10]

            # Attach behavior signals captured from JS hooks
            scan_result["js_behavior_signals"] = js_alerts
            scan_result["threat_detected"] = (
                js_alerts.get("clipboard_write_detected")
                or js_alerts.get("suspicious_redirect")
                or js_alerts.get("keylogger_like_behavior")
                or js_alerts.get("crypto_mining_like_behavior")
                or js_alerts.get("form_data_exfil_like_behavior")
            )

            scan_result["status"] = "success"
            
            logger.info("Sandbox execution completed successfully.")

        except PlaywrightTimeoutError:
            error_msg = "Execution timed out. Tarpitting detected."
            scan_result["error_message"] = error_msg
            
        except Exception as e:
            error_msg = f"Browser failure: {str(e)}"
            scan_result["error_message"] = error_msg
            
        finally:
            if 'browser' in locals():
                await browser.close()

    return scan_result

def _run_in_fresh_loop(target_url: str) -> dict:
    """Run detonate_url inside a brand-new event loop (no FastAPI/uvicorn loop conflict)."""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(detonate_url(target_url))
    finally:
        loop.close()


async def run_url_scanner(target_url: str) -> dict:
    """Execute Playwright sandbox in a separate thread with a fresh event loop."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(pool, _run_in_fresh_loop, target_url)


