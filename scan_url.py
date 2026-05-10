import os
import asyncio
import logging
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright, TimeoutError as PlaywrightTimeoutError

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

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
            browser = await p.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-setuid-sandbox", "--disable-dev-shm-usage", "--blink-settings=imagesEnabled=false"]
            )
            
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                ignore_https_errors=True
            )
            
            page = await context.new_page()
            page.on("dialog", lambda dialog: asyncio.create_task(dialog.dismiss()))

            # Track unique domains contacted in background
            async def handle_response(response):
                try:
                    domain = response.url.split('/')[2]
                    network_domains.add(domain)
                except:
                    pass

            page.on("response", handle_response)

            logger.info("Loading DOM...")
            await page.goto(target_url, wait_until="domcontentloaded", timeout=10000)
            
            # Wait only 1.5 seconds for delayed text to render
            await page.wait_for_timeout(1500)
            
            raw_html = await page.content()
            
            # Extract pure visible text for Groq Llama
            soup = BeautifulSoup(raw_html, 'html.parser')
            for script in soup(["script", "style", "noscript", "meta"]):
                script.extract()
            
            extracted_text = soup.get_text(separator=' ', strip=True)
            
            scan_result["extracted_text"] = extracted_text[:6000] # Limit to 6000 chars for token safety
            scan_result["network_traffic"] = list(network_domains)[:10]
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

def run_url_scanner(target_url: str) -> dict:
    return asyncio.run(detonate_url(target_url))