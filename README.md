# wraphp3r
<img src=wraphp3r.png>
Simple and powerful tool for testing LFI (Local File Inclusion) vulnerabilities via PHP wrappers.
<p><b>Refactor:</b> Tool has been refactored to version 2.0. Please use <code>-h</code> flag to use new functions.</p>

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
git clone https://github.com/csshark/wraphp3r.git
```
## Example usage:
<pre><code>python3 wraphp3r.py -v --smart "http://example.com/image" id</code></pre>
This will produce <code>/image?id={payload}</code> smart tests.
