#!/usr/bin/env python3
  
import requests
import argparse
import re
import sys
import subprocess
from urllib.parse import urlparse


class UFX:
    def __init__(self, domain, specific_pattern=None, use_filter=False):
        self.domain = domain
        self.specific_pattern = specific_pattern
        self.use_filter = use_filter
        self.patterns = {
            "flags": "-iE",
            "patterns": [
                "q=", "s=", "search=", "lang=", "keyword=", "query=",
                "page=", "keywords=", "year=", "view=", "email=",
                "type=", "name=", "p=", "callback=", "jsonp=",
                "api_key=", "api=", "password=", "email=", "emailto=",
                "token=", "username=", "csrf_token=", "unsubscribe_token=",
                "id=", "item=", "page_id=", "month=", "immagine=",
                "list_type=", "url=", "terms=", "categoryid=",
                "key=", "l=", "begindate=", "enddate="
            ]
        }
        self.xss_indicators = [
            "<script", "javascript:", "onerror=",
            "onload=", "alert(", "prompt(", "confirm(",
            "eval(", "document.cookie", "document.location"
        ]
        # If a specific pattern is provided, use only that pattern.
        if self.specific_pattern:
            self.patterns["patterns"] = [self.specific_pattern]

    def get_wayback_urls(self):
        """Fetch URLs from Wayback Machine."""
        wayback_url = "https://web.archive.org/cdx/search/cdx"
        params = {
            "url": f"*.{self.domain}/*",
            "collapse": "urlkey",
            "output": "text",
            "fl": "original",
            "limit": 50000
        }
        try:
            response = requests.get(wayback_url, params=params, timeout=30)
            response.raise_for_status()
            return list(set(url.strip() for url in response.text.splitlines() if url.strip()))
        except requests.RequestException as e:
            print(f"[!] Error fetching Wayback URLs: {e}")
            return []

    def get_alienvault_urls(self):
        """Fetch URLs using AlienVault OTX API."""
        url = f"https://otx.alienvault.com/api/v1/indicators/hostname/{self.domain}/url_list"
        params = {"limit": 500, "page": 1}
        try:
            response = requests.get(url, params=params, timeout=30)
            response.raise_for_status()
            data = response.json()
            return [entry["url"] for entry in data.get("url_list", [])]
        except requests.RequestException as e:
            print(f"[!] Error fetching AlienVault URLs: {e}")
            return []

    def filter_urls(self, urls):
        """Filter URLs using s0md3v's uro tool."""
        try:
            process = subprocess.Popen(
                ["uro"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            stdout, stderr = process.communicate("\n".join(urls))
            if process.returncode != 0:
                print(f"[!] Error running uro: {stderr}")
                return urls  # Return unfiltered URLs if uro fails
            return stdout.splitlines()
        except FileNotFoundError:
            print("[!] 'uro' tool not found. Make sure it's installed and in your PATH.")
            return urls

    def is_potential_xss(self, url):
        """Advanced XSS detection."""
        try:
            parsed_url = urlparse(url)
            query_params = parsed_url.query
            for pattern in self.patterns["patterns"]:
                if pattern in query_params:
                    param_values = re.findall(f"{pattern}([^&]*)", url)
                    for value in param_values:
                        if any(indicator.lower() in value.lower() for indicator in self.xss_indicators):
                            return True
                    if len(query_params) > 0 and len(query_params) < 200:
                        return True
            return False
        except Exception:
            return False

    def run(self):
        """Main execution method."""
        print(f"[*] Scanning domain: {self.domain}")
        if self.specific_pattern:
            print(f"[*] Using specific pattern: {self.specific_pattern}")
        
        # Fetch URLs from various sources
        wayback_urls = self.get_wayback_urls()
        alienvault_urls = self.get_alienvault_urls()

        # Combine and deduplicate URLs
        all_urls = set(wayback_urls + alienvault_urls)
        print(f"[+] Total unique URLs fetched: {len(all_urls)}")

        # Filter URLs if the --filter option is used
        if self.use_filter:
            print("[*] Filtering URLs with uro...")
            all_urls = self.filter_urls(all_urls)
            print(f"[+] Total URLs after filtering: {len(all_urls)}")
        
        # Find XSS-vulnerable URLs
        vulnerable_urls = [
            url for url in all_urls if self.is_potential_xss(url)
        ]
        return vulnerable_urls


def main():
    parser = argparse.ArgumentParser(
        description="UFX - URL FOR XSS ",
        epilog="Example: python3 ufx.py -d example.com -o results.txt"
    )
    parser.add_argument(
        "-d", "--domain", required=True,
        help="Target domain to scan (e.g., example.com)"
    )
    parser.add_argument(
        "-o", "--output", type=str,
        help="Save results to the specified output file"
    )
    parser.add_argument(
        "-sp", "--specific-pattern", type=str,
        help="Scan using a specific pattern (e.g., q=)"
    )
    parser.add_argument(
        "--filter", action="store_true",
        help="Filter URLs using s0md3v's uro tool"
    )

    args = parser.parse_args()
    
    try:
        ufx = UFX(args.domain, args.specific_pattern, args.filter)
        vulnerable_urls = ufx.run()
        
        if vulnerable_urls:
            print("[!] Potential XSS target URLs:")
            for url in vulnerable_urls:
                print(url)
            
            # Save results to file if specified
            if args.output:
                with open(args.output, 'w') as f:
                    f.write("\n".join(vulnerable_urls))
                print(f"[+] Results saved to {args.output}")
        else:
            print("[*] No potential XSS target found")
    
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
