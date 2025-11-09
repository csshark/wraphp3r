# wraphp3r - LFI via PHP wrappers scanner
<img src=wraphp3r.png>
Simple and powerful tool for testing LFI (Local File Inclusion) vulnerabilities via PHP wrappers.

## Description

Quick scanner that tests URLs for LFI vulnerabilities using comprehensive techniques:
- PHP Version detection to use perfect payload
- PHP filter wrappers (base64, iconv, zlib, rot13, etc.)
- Path traversal payloads with various encoding bypasses
- Data wrappers for RCE testing
- Expect wrappers for command execution
- RFI payloads for remote file inclusion
- Support for self-signed certificates and proxy 

## Clone Repo

```bash
git clone https://github.com/csshark/lfi-wrapper-scanner.git
```
## Example usage:
<pre><code>python3 lfi_scanner.py http://example.com/test.php file</code></pre>
