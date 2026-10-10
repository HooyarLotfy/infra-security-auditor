#!/usr/bin/env python3
"""
UI Health Scanner (Playwright-based)
------------------------------------
Visits a list of sites, captures console errors, and scans navigation links.
"""

import json
import asyncio
import os
from playwright.async_api import async_playwright

MAX_NAV_LINKS = 3 # Number of navbar links to check per site
TIMEOUT = 30000 # 30 seconds

async def scan_url(browser, url):
    page_report = {
        "url": url,
        "status": "Success",
        "console_logs": [],
        "errors": []
    }
    
    page = await browser.new_page()
    
    # Capture console logs
    page.on("console", lambda msg: page_report["console_logs"].append({
        "type": msg.type,
        "text": msg.text,
        "location": msg.location
    }) if msg.type in ["error", "warning"] else None)
    
    page.on("pageerror", lambda exc: page_report["errors"].append(str(exc)))

    try:
        print(f"[*] Navigating to {url}...")
        await page.goto(url, timeout=TIMEOUT, wait_until="networkidle")
        
        # Extract Navbar links
        nav_links = await page.evaluate(f"""() => {{
            const links = Array.from(document.querySelectorAll('nav a, header a, .navbar a'));
            const currentHost = window.location.hostname;
            return links
                .map(a => a.href)
                .filter(href => href.startsWith('http') && href.includes(currentHost))
                .slice(0, {MAX_NAV_LINKS});
        }}""")
        
        page_report["nav_links_found"] = nav_links
        
    except Exception as e:
        page_report["status"] = f"Failed: {str(e)}"
        page_report["nav_links_found"] = []
    
    await page.close()
    return page_report

async def main():
    if not os.path.exists("domains.json"):
        print("[-] Error: domains.json not found. Run site_url_extractor.py first.")
        return

    with open("domains.json", "r") as f:
        sites = json.load(f)

    report = {}

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        
        for site_url in sites:
            print(f"\n[+] Auditing site: {site_url}")
            site_data = {"home": await scan_url(browser, site_url), "inner_pages": []}
            
            # Audit navbar links
            for link in site_data["home"].get("nav_links_found", []):
                # Don't re-audit home
                if link.rstrip('/') == site_url.rstrip('/'): continue
                print(f"    - Checking internal link: {link}")
                link_report = await scan_url(browser, link)
                site_data["inner_pages"].append(link_report)
                
            report[site_url] = site_data

        await browser.close()

    with open("ui_health_report.json", "w") as f:
        json.dump(report, f, indent=4)
    
    print(f"\n[!] Comprehensive report generated: ui_health_report.json")

if __name__ == "__main__":
    asyncio.run(main())
