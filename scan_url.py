import asyncio
import logging
import base64
import concurrent.futures
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

# Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger("aeglis.sandbox")
logger.setLevel(logging.WARNING)

# Silence noisy third-party loggers
for _noisy in ("httpx", "websockets", "playwright", "asyncio"):
    logging.getLogger(_noisy).setLevel(logging.ERROR)

# Use lxml when available, with the standard parser as a fallback.
try:
    import lxml  # noqa: F401
    _HTML_PARSER = "lxml"
except ImportError:
    _HTML_PARSER = "html.parser"

# Chromium launch arguments. These options reduce memory use per launch.
_CHROMIUM_ARGS = [
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-dev-shm-usage",       # Use /tmp instead of /dev/shm (Docker-safe)
    "--disable-gpu",                  # No GPU in headless — saves GPU process memory
    "--no-first-run",                 # Skip first-run setup tasks
    "--no-default-browser-check",
    "--disable-background-networking",# No background sync/fetches
    "--disable-background-timer-throttling",
    "--disable-backgrounding-occluded-windows",
    "--disable-renderer-backgrounding",
    "--disable-sync",                 # No Chrome account sync
    "--disable-translate",            # No Google Translate
    "--disable-extensions",
    "--disable-default-apps",
    "--disable-component-update",
    "--mute-audio",                   # No audio process
    "--hide-scrollbars",
    "--metrics-recording-only",
    "--safebrowsing-disable-auto-update",
    "--js-flags=--max-old-space-size=256",  # Cap V8 heap to 256 MB
]


async def detonate_url(target_url: str) -> dict:
    """
    Aeglis Dynamic Sandbox — headless Chromium execution for threat detonation.
    Captures: screenshot (viewport), visible text, network traffic, JS behavior signals.
    Target scan time: <3.5s | RAM per scan: ~150-200 MB
    """
    network_domains: set = set()
    final_urls:      list = []

    scan_result = {
        "target_url":    target_url,
        "status":        "failed",
        "error_message": None,
        "network_traffic":    [],
        "extracted_text":     None,
        "screenshot_base64":  None,
        "redirect_chain":     [],
        "js_behavior_signals":{},
        "threat_detected":    False,
    }

    async with async_playwright() as p:
        browser = None
        try:
            browser = await p.chromium.launch(
                headless=True,
                args=_CHROMIUM_ARGS,
            )

            context = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1280, "height": 800},  # Explicit viewport (screenshot size control)
                ignore_https_errors=True,
            )

            page = await context.new_page()

            # Dismiss JavaScript dialogs automatically.
            page.on("dialog", lambda d: asyncio.create_task(d.dismiss()))

            # Track suspicious JavaScript behavior.
            js_alerts = {
                "clipboard_write_detected":    False,
                "suspicious_redirect":         False,
                "keylogger_like_behavior":     False,
                "crypto_mining_like_behavior": False,
                "form_data_exfil_like_behavior":False,
            }

            # Inject clipboard hijack detector before page scripts run
            await page.add_init_script("""
                () => {
                    const orig = navigator.clipboard && navigator.clipboard.writeText;
                    if (orig) {
                        navigator.clipboard.writeText = function(...args) {
                            window.__AeglisClipboardWrite = true;
                            return orig.apply(this, args);
                        };
                    }
                }
            """)

            # Copy browser-side behavior flags into the Python result.
            async def sync_js_markers():
                try:
                    if await page.evaluate("() => window.__AeglisClipboardWrite === true"):
                        js_alerts["clipboard_write_detected"] = True
                except Exception:
                    pass

            # Track redirects in the main frame.
            async def handle_navigation(frame):
                try:
                    if frame != page.main_frame:
                        return
                    current = frame.url
                    if current and current != target_url and not current.startswith("about:"):
                        final_urls.append(current)
                        if len(set(final_urls)) >= 2:
                            js_alerts["suspicious_redirect"] = True
                except Exception:
                    pass

            page.on("framenavigated", lambda f: asyncio.create_task(handle_navigation(f)))

            # Detect possible data exfiltration and crypto-mining requests.
            _EXFIL_SIGNALS   = {"collect", "exfil", "steal", "bot", "miner", "mine", "stratum"}
            _MINING_SIGNALS  = {"miner", "mining", "stratum", "hashrate"}
            _SENSITIVE_KEYS  = {"login", "auth", "password", "wallet", "seed", "mnemonic", "keystore"}

            async def handle_request(req):
                try:
                    url_lower = req.url.lower()
                    if req.method in ("POST", "PUT") or any(k in url_lower for k in _SENSITIVE_KEYS):
                        if any(x in url_lower for x in _EXFIL_SIGNALS):
                            js_alerts["form_data_exfil_like_behavior"] = True
                    if any(x in url_lower for x in _MINING_SIGNALS):
                        js_alerts["crypto_mining_like_behavior"] = True
                except Exception:
                    pass

            page.on("request", lambda r: asyncio.create_task(handle_request(r)))

            # Probe for exposed event-listener inspection APIs as a weak keylogger signal.
            # getEventListeners is normally available only in DevTools.
            async def probe_keylogger():
                try:
                    if await page.evaluate(
                        "() => !!(window.getEventListeners && window.getEventListeners(window))"
                    ):
                        js_alerts["keylogger_like_behavior"] = True
                except Exception:
                    pass

            page.on("domcontentloaded", lambda: asyncio.create_task(probe_keylogger()))

            # Track domains contacted by page responses.
            async def handle_response(response):
                try:
                    network_domains.add(response.url.split("/")[2])
                except Exception:
                    pass

            page.on("response", handle_response)

    
            # Main execution

            # 1. Navigate to the target URL.
            print(f"\n[DEBUG - PLAYWRIGHT] 🌐 Loading URL: {target_url}")
            try:
                # Allow extra time for slow but legitimate sites.
                await page.goto(target_url, wait_until="domcontentloaded", timeout=8000)
                print("[DEBUG - PLAYWRIGHT] ✅ Page loaded successfully within 8s.")
            except Exception as e:
                # Continue so any available page content can still be captured.
                print(f"[DEBUG - PLAYWRIGHT] ⚠️ Timeout/Error during goto: {e}. Trying to continue...")
                pass
            # Capture post-navigation URL (handles js redirects)
            try:
                final_urls.append(page.url)
            except Exception:
                pass

            # 2. Allow dynamic content to settle.
            await page.wait_for_timeout(1000)

            # 3. Copy browser-side behavior flags into the result.
            await sync_js_markers()

            # 4. Extract the raw HTML.
            raw_html = await page.content()

            # 5. Capture only the initial viewport to reduce image size.
            print("[DEBUG - PLAYWRIGHT] 📸 Attempting to capture screenshot...")
            try:
                screenshot_bytes = await page.screenshot(
                    type="jpeg",
                    quality=50,
                    full_page=False,   # Most phishing content appears above the fold.
                )
                scan_result["screenshot_base64"] = base64.b64encode(screenshot_bytes).decode("utf-8")
                print(f"[DEBUG - PLAYWRIGHT] ✅ Screenshot captured! Base64 Length: {len(scan_result['screenshot_base64'])}")
            except Exception as e:
                print(f"[DEBUG - PLAYWRIGHT] ❌ SCREENSHOT FAILED: {e}")
                scan_result["screenshot_base64"] = None

            # 6. Extract visible text from the page.
            soup = BeautifulSoup(raw_html, _HTML_PARSER)
            for tag in soup(["script", "style", "noscript", "meta", "head"]):
                tag.extract()

            extracted_text = soup.get_text(separator=" ", strip=True)

            # 7. Assemble the scan result.
            scan_result["extracted_text"]  = extracted_text[:10000]  # Keep the AI context bounded.
            scan_result["network_traffic"] = list(network_domains)[:10]
            scan_result["redirect_chain"]  = list(dict.fromkeys(final_urls))[-10:]  # dedupe, last 10

            scan_result["js_behavior_signals"] = js_alerts
            scan_result["threat_detected"] = any([
                js_alerts["clipboard_write_detected"],
                js_alerts["suspicious_redirect"],
                js_alerts["keylogger_like_behavior"],
                js_alerts["crypto_mining_like_behavior"],
                js_alerts["form_data_exfil_like_behavior"],
            ])

            scan_result["status"] = "success"

        except PlaywrightTimeoutError:
            scan_result["error_message"] = "Execution timed out. Tarpitting or dead domain detected."

        except Exception as e:
            scan_result["error_message"] = f"Browser failure: {e}"

        finally:
            if browser:
                try:
                    await context.close()   # Release page resources before closing the browser.
                except Exception:
                    pass
                await browser.close()

    return scan_result


# Thread isolation

def _run_in_fresh_loop(target_url: str) -> dict:
    """
    Run detonate_url in a brand-new event loop.
    Required to avoid FastAPI/uvicorn loop conflict with Playwright's own loop.
    """
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(detonate_url(target_url))
    finally:
        loop.close()


async def run_url_scanner(target_url: str) -> dict:
    """Public entry point — executes Playwright sandbox in isolated thread."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(pool, _run_in_fresh_loop, target_url)
