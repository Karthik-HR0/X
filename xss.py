import os
import time
import sys
import logging
import asyncio
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from webdriver_manager.chrome import ChromeDriverManager
from colorama import Fore
import argparse
import urllib3

logging.basicConfig(level=logging.ERROR)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def load_payloads(payload_file):
    try:
        with open(payload_file, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error loading payloads: {e}")
        sys.exit(0)


def generate_payload_urls(url, payload):
    url_combinations = []
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    if not scheme:
        scheme = 'http'
    query_params = parse_qs(query_string, keep_blank_values=True)
    for key in query_params.keys():
        modified_params = query_params.copy()
        modified_params[key] = [payload]
        modified_query_string = urlencode(modified_params, doseq=True)
        modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
        url_combinations.append(modified_url)
    return url_combinations


async def check_vulnerability(url, payloads, vulnerable_urls, total_scanned, driver):
    for payload in payloads:
        payload_urls = generate_payload_urls(url, payload)
        if not payload_urls:
            continue
        for payload_url in payload_urls:
            print(Fore.YELLOW + f"[→] Scanning payload: {payload}")
            try:
                driver.get(payload_url)
                total_scanned[0] += 1
                try:
                    WebDriverWait(driver, 1).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    alert_text = alert.text

                    if alert_text:
                        result = Fore.GREEN + f"[✓] Vulnerable: {payload_url} - Alert Text: {alert_text}"
                        print(result)
                        vulnerable_urls.append(payload_url)
                    alert.accept()
                except TimeoutException:
                    print(Fore.RED + f"[✗] Not Vulnerable: {payload_url}")
            except UnexpectedAlertPresentException:
                continue


async def scan(urls, payloads, vulnerable_urls, total_scanned, concurrency, driver):
    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    for url in urls:
        tasks.append(bound_check(url, semaphore, payloads, vulnerable_urls, total_scanned, driver))
    await asyncio.gather(*tasks)


async def bound_check(url, semaphore, payloads, vulnerable_urls, total_scanned, driver):
    async with semaphore:
        await check_vulnerability(url, payloads, vulnerable_urls, total_scanned, driver)


def run_scan(urls, payload_file, concurrency, timeout):
    payloads = load_payloads(payload_file)
    vulnerable_urls = []
    total_scanned = [0]

    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")

    logging.getLogger('urllib3').setLevel(logging.CRITICAL)

    driver_service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=driver_service, options=chrome_options)

    try:
        asyncio.run(scan(urls, payloads, vulnerable_urls, total_scanned, concurrency, driver))
    except Exception as e:
        print(Fore.RED + f"[!] Error during scan: {e}")
    finally:
        driver.quit()

    return vulnerable_urls, total_scanned[0]


def print_scan_summary(total_found, total_scanned, start_time):
    print(Fore.CYAN + "\n→ Scanning finished.")
    print(Fore.YELLOW + f"• Total found: {Fore.GREEN}{total_found}")
    print(Fore.YELLOW + f"• Total scanned: {total_scanned}")
    print(Fore.YELLOW + f"• Time taken: {int(time.time() - start_time)} seconds")


def main():
    parser = argparse.ArgumentParser(description="XSS Scanner Tool")
    parser.add_argument("-url", help="Specify a single URL to scan", type=str)
    parser.add_argument("-file", help="Specify a file containing URLs", type=str)
    parser.add_argument("-payload", help="Specify a payload file", type=str, required=True)
    args = parser.parse_args()

    urls = []
    if args.url:
        urls.append(args.url)
    elif args.file:
        try:
            with open(args.file, "r") as file:
                urls = [line.strip() for line in file if line.strip()]
        except FileNotFoundError:
            print(Fore.RED + f"[!] File not found: {args.file}")
            sys.exit(0)
    else:
        # Handle piped input
        if not sys.stdin.isatty():
            urls = [line.strip() for line in sys.stdin if line.strip()]
        else:
            print(Fore.RED + "[!] You must specify -url, -file, or provide URLs via pipe.")
            sys.exit(0)

    print(Fore.CYAN + "[i] Starting scan...\n")

    total_scanned = 0
    start_time = time.time()
    all_vulnerable_urls = []

    try:
        for url in urls:
            print(Fore.YELLOW + f"\n→ Scanning URL: {url}")
            vulnerable_urls, scanned = run_scan([url], args.payload, concurrency=10, timeout=1)

            all_vulnerable_urls.extend(vulnerable_urls)
            total_scanned += scanned
    except KeyboardInterrupt:
        print(Fore.RED + "\nScan interrupted by user.\n")

    print_scan_summary(len(all_vulnerable_urls), total_scanned, start_time)


if __name__ == "__main__":
    main()
