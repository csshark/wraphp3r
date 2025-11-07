# LFI via PHP Wrappers Scanner 
<img src=wraphp3r.png>
Simple tool created written in PHP for PHP! It scans for LFI via PHPWrappers. Script has been created for my own purpose but it might actually help some of you find vulnerabilities. 

## Requirements
PHP-cURL:
<pre><code>sudo apt install php-curl</code></pre>

## Usage: 
<pre><code>php wraphp3r "https://vulnerabletarget.com/index.php" "file"
php wraphp3r "https://vulnerabletarget.com/index.php" "page" --file "/another/sensitivefile1</code></pre>
