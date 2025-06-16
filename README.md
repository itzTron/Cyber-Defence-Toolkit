# Cyber-Defence-Toolkit
# 🔒 Cyber-Defence Toolkit

A comprehensive CLI security suite featuring file encryption, access logging, integrity verification, and password management.

![Demo](https://i.imgur.com/Jf4XbKv.gif) *(Example GIF - replace with actual screenshot)*

## 🚀 Features

- **AES-256 File Encryption/Decryption**
- **Access Logging with Geolocation**
- **File Integrity Checks (MD5/SHA256)**
- **Password Generator & Strength Analyzer**
- **Cross-Platform (Windows/Linux/macOS)**
- **SQLite Database Backend**

## 📦 Installation

### Prerequisites
- Python 3.8+
- Git (optional)

### Step-by-Step Setup

#### Windows
```powershell
# 1. Clone repository
git clone https://github.com/yourusername/cyber-defence-toolkit.git
cd cyber-defence-toolkit

# 2. Install dependencies
pip install pycryptodome geoip2 python-dotenv colorama

# 3. Download GeoIP database (Free license required)
python -c "import urllib.request; urllib.request.urlretrieve('https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=YOUR_KEY&suffix=tar.gz', 'GeoLite2-City.tar.gz')"
tar -xf GeoLite2-City.tar.gz
move GeoLite2-City_*\GeoLite2-City.mmdb .
rmdir /s /q GeoLite2-City_*
del GeoLite2-City.tar.gz

