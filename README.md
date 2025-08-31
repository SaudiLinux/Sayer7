# Sayer7 - أداة استطلاع متقدمة لتطبيقات الويب
# Sayer7 - Advanced Web Application Reconnaissance Tool

<div align="center">

[![Sayer7](https://img.shields.io/badge/Sayer7-v1.0.0-red.svg)](https://github.com/SaudiLinux/Sayer7)
[![Python](https://img.shields.io/badge/Python-3.7+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-GPL%20v3-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20|%20Linux%20|%20macOS-lightgrey.svg)](https://github.com/SaudiLinux/Sayer7)

**Sayer7 هي أداة استطلاع متقدمة مصممة لجعل استطلاع تطبيقات الويب أمرًا بسيطًا**

**Sayer7 is an advanced reconnaissance tool designed to make web application reconnaissance simple**

</div>

## 🌟 المميزات الرئيسية | Key Features

### اللغة العربية
- 🔍 **محرك تحليل URL مدمج وقوي**
- 🌐 **توافق مع محركات بحث متعددة** (DuckDuckGo، AOL، Bing، Google)
- 🚫 **تجاوز حظر IP من خلال استخراج عناوين URL من Google Cache**
- 🔗 **دعم الوكيل الكامل** (HTTP، HTTPS، SOCKS4، SOCKS5، Tor)
- 🛡️ **تحليل ملفات robots.txt و sitemap.xml**
- 🎯 **تقييمات الثغرات الأمنية المتعددة** (XSS، SQLi، Clickjacking، مسح المنافذ، إلخ)
- 🎭 **تشفير وتمويه حمولات XSS**
- 🔄 **دعم أكثر من 4000 وكيل مستخدم عشوائي**
- 🕷️ **زحف شامل لصفحات الويب**
- 🛡️ **تحديد WAF/IPS/IDS لأكثر من 20 جدار حماية مختلف**
- 📊 **تعداد حماية الرؤوس HTTP**
- 📝 **حفظ السجلات والمعلومات الحيوية**

### English
- 🔍 **Powerful built-in URL analysis engine**
- 🌐 **Multi-search engine compatibility** (DuckDuckGo, AOL, Bing, Google)
- 🚫 **IP ban bypass through Google Cache URL extraction**
- 🔗 **Full proxy support** (HTTP, HTTPS, SOCKS4, SOCKS5, Tor)
- 🛡️ **robots.txt and sitemap.xml analysis**
- 🎯 **Multiple vulnerability assessments** (XSS, SQLi, Clickjacking, port scanning, etc.)
- 🎭 **XSS payload encryption and obfuscation**
- 🔄 **Support for 4000+ random user agents**
- 🕷️ **Comprehensive web crawling**
- 🛡️ **WAF/IPS/IDS detection for 20+ different firewalls**
- 📊 **HTTP headers protection enumeration**
- 📝 **Logging and vital information saving**

## 🔧 فحوصات الثغرات الأمنية | Security Vulnerability Checks

### SSL/TLS Vulnerabilities
- ❤️ **HEARTBLEED** - OpenSSL vulnerability
- 🔒 **FREAK** - Factoring attack on RSA-EXPORT Keys
- 🐕 **POODLE** - SSLv3 vulnerability
- 💉 **CCS Injection** - ChangeCipherSpec injection
- 🔨 **LOGJAM** - Diffie-Hellman key exchange vulnerability
- 🌊 **DROWN** - Decrypting RSA with Obsolete and Weakened eNcryption
- 🐻 **BEAST** - Browser Exploit Against SSL/TLS
- 🦀 **CRIME** - Compression Ratio Info-leak Made Easy
- 🌊 **BREACH** - Browser Reconnaissance and Exfiltration via Adaptive Compression
- 🍀 **LUCKY13** - TLS CBC cipher vulnerability

### DNS Security Checks
- 🔄 **DNS Zone Transfer** testing
- 🎯 **Subdomain brute-force** attacks
- 🔍 **DNS record enumeration** (A, AAAA, MX, NS, TXT, CNAME)
- 🛡️ **DNSSEC validation**

### Web Application Security
- 🎯 **XSS (Cross-Site Scripting)** detection
- 💉 **SQL Injection** testing
- 🖱️ **Clickjacking** vulnerability assessment
- 🚪 **Admin panel discovery**
- 🔍 **Directory and file brute-force**
- 🌐 **Port scanning** for common services

## 🚀 التثبيت السريع | Quick Installation

### الخطوة الواحدة | One-Step Installation

```bash
# Clone the repository
git clone https://github.com/SaudiLinux/Sayer7.git
cd Sayer7

# Run the automated installer
python install.py
```

### التثبيت اليدوي | Manual Installation

```bash
# Clone the repository
git clone https://github.com/SaudiLinux/Sayer7.git
cd Sayer7

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows:
venv\\Scripts\\activate
# Linux/macOS:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run Sayer7
python Sayer7.py --help
```

## 📖 الاستخدام | Usage

### الأوامر الأساسية | Basic Commands

```bash
# Scan a single URL
python Sayer7.py -u https://example.com

# Full security scan
python Sayer7.py -u https://example.com --full

# Use proxy
python Sayer7.py -u https://example.com --proxy 127.0.0.1:8080

# Search for vulnerabilities
python Sayer7.py -u https://example.com --scan xss,sqli

# Custom user agent
python Sayer7.py -u https://example.com --user-agent "Custom Agent"

# Output to file
python Sayer7.py -u https://example.com -o results.json
```

### أوامر البحث المتقدمة | Advanced Search Commands

```bash
# Search using Google dorks
python Sayer7.py --search "site:example.com" --engine google

# Search with specific filetype
python Sayer7.py --search "filetype:pdf site:example.com"

# Subdomain enumeration
python Sayer7.py -u https://example.com --subdomains

# Port scanning
python Sayer7.py -u https://example.com --ports 80,443,8080

# SSL/TLS analysis
python Sayer7.py -u https://example.com --ssl-check
```

## 🎯 أمثلة عملية | Practical Examples

### مثال 1: فحص شامل | Comprehensive Scan
```bash
python Sayer7.py -u https://target.com --full --proxy 127.0.0.1:8080 --output results/
```

### مثال 2: فحص الثغرات | Vulnerability Scan
```bash
python Sayer7.py -u https://target.com --scan xss,sqli,clickjacking --payloads custom.txt
```

### مثال 3: استكشاف الشبكة | Network Discovery
```bash
python Sayer7.py -u https://target.com --subdomains --ports 1-1000 --dns-zone-transfer
```

### مثال 4: تجاوز WAF | WAF Bypass
```bash
python Sayer7.py -u https://target.com --waf-bypass --tor --random-ua
```

## ⚙️ الإعدادات | Configuration

### ملف الإعدادات | Configuration File

يتم تخزين الإعدادات في `config/config.json`:

```json
{
  "general": {
    "timeout": 30,
    "max_threads": 50,
    "user_agent": "Sayer7/1.0",
    "output_format": "json"
  },
  "proxy": {
    "enabled": false,
    "type": "http",
    "host": "127.0.0.1",
    "port": 8080
  },
  "search_engines": {
    "delay": 1,
    "max_results": 100
  },
  "vulnerability_scanning": {
    "xss_payloads_file": "config/xss_payloads.txt",
    "sqli_payloads_file": "config/sqli_payloads.txt"
  }
}
```

## 🛠️ المتطلبات | Requirements

### Python Packages
- Python 3.7+
- All dependencies listed in `requirements.txt`

### System Dependencies
- **Linux**: `nmap`, `dnsutils`, `whois`
- **macOS**: `nmap`, `dnsutils` (via Homebrew)
- **Windows**: Built-in support (nmap recommended)

## 🔄 التحديث | Updates

```bash
# Update Sayer7
git pull origin main
python install.py
```

## 🐛 الإبلاغ عن المشاكل | Bug Reports

للإبلاغ عن مشاكل أو طلب مميزات جديدة:
- GitHub Issues: [https://github.com/SaudiLinux/Sayer7/issues](https://github.com/SaudiLinux/Sayer7/issues)
- Email: SayerLinux1@gmail.com

## 📄 الترخيص | License

هذا المشروع مرخص تحت GPL v3.0 | This project is licensed under GPL v3.0

## 👤 المؤلف | Author

**SayerLinux**
- GitHub: [https://github.com/SaudiLinux](https://github.com/SaudiLinux)
- Email: SayerLinux1@gmail.com
- Website: [https://github.com/SaudiLinux/Sayer7](https://github.com/SaudiLinux/Sayer7)

## 🤝 المساهمة | Contributing

نرحب بالمساهمات! يرجى قراءة ملف CONTRIBUTING.md للحصول على التفاصيل.
Contributions are welcome! Please read CONTRIBUTING.md for details.

## 🙏 الشكر | Acknowledgments

- شكر خاص لمجتمع الأمن السيبراني
- Special thanks to the cybersecurity community
- شكر لجميع المساهمين في المشروع
- Thanks to all project contributors

---

<div align="center">

**⭐ إذا وجدت Sayer7 مفيداً، يرجى إعطاء نجمة على GitHub! ⭐**

**⭐ If you find Sayer7 useful, please give it a star on GitHub! ⭐**

</div>