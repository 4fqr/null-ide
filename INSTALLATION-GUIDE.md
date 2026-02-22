# Null IDE - Installation Guide

## 🎯 **Null-IDE-Installer.exe**

**Size:** 86.45 MB  
**Location:** `release/Null-IDE-Installer.exe`

---

## ✨ **Features**

### **1. "Open with Null IDE" Context Menu**

After installation, you'll see "Open with Null IDE" when you:

- **Right-click any file** → "Open with Null IDE"
- **Right-click any folder** → "Open with Null IDE" 
- **Right-click inside a folder** (on background) → "Open Null IDE here"

Supported file types automatically associated:
- JavaScript (.js, .jsx)
- TypeScript (.ts, .tsx)
- Python (.py)
- Java (.java)
- C/C++ (.c, .cpp)
- HTML/CSS (.html, .css)
- JSON (.json)
- Markdown (.md)
- Text files (.txt)

### **2. Installation Options**

- **Custom installation directory** (default: `C:\Program Files\Null IDE`)
- **Desktop shortcut** - Quick access from desktop
- **Start Menu shortcuts** - Find in Windows Start Menu
- **Per-machine installation** - Available for all users
- **Automatic uninstaller** - Clean removal when needed

### **3. Complete Package**

The installer includes:
- ✅ No source code (production build only)
- ✅ All dependencies bundled
- ✅ Works on any Windows PC (x64)
- ✅ No additional installations required
- ✅ Fully portable after installation

---

## 📦 **Installation Steps**

1. **Run** `Null-IDE-Installer.exe`
2. **Choose** installation directory (or use default)
3. **Wait** for installation to complete (~2 minutes)
4. **Launch** from Desktop or Start Menu
5. **Test** context menu: Right-click any file/folder

---

## 🔧 **What Gets Installed**

```
C:\Program Files\Null IDE\
├── Null IDE.exe          (Main application)
├── resources\            (Application resources)
├── locales\              (Language files)
└── uninstall.exe         (Uninstaller)
```

**Registry Entries:**
- `HKEY_CLASSES_ROOT\*\shell\OpenWithNullIDE` (File context menu)
- `HKEY_CLASSES_ROOT\Directory\shell\OpenWithNullIDE` (Folder context menu)
- `HKEY_CLASSES_ROOT\Directory\Background\shell\OpenWithNullIDE` (Background context menu)
- `HKEY_LOCAL_MACHINE\Software\NullSec\NullIDE` (App settings)
- File associations for .js, .ts, .py, .html, .css, etc.

---

## 🗑️ **Uninstallation**

### Method 1: Control Panel
1. Open Windows Settings
2. Go to Apps & Features
3. Find "Null IDE"
4. Click Uninstall

### Method 2: Uninstaller
1. Navigate to `C:\Program Files\Null IDE\`
2. Run `uninstall.exe`

**What gets removed:**
- ✅ All application files
- ✅ Desktop & Start Menu shortcuts
- ✅ All registry entries
- ✅ Context menu entries
- ✅ File associations

---

## 🛠️ **Advanced Hacking Toolkit**

### Reconnaissance Tools
- **Subdomain Enumerator** - Discover subdomains
- **Reverse DNS Lookup** - IP to hostname
- **Port Sweeper** - Advanced port scanning

### Payload Generation
- **Reverse Shell Generator** - Multi-language shells
- **SQLi Payload Generator** - Injection attacks
- **XSS Payload Generator** - Cross-site scripting

### Cryptography & Hashing
- **Multi-Hash Generator** - MD5, SHA-1, SHA-256
- **JWT Decoder** - JSON Web Token analysis
- **Multi-Encoding Tool** - Base64, URL, HTML, Hex

### Web Exploitation
- **LFI/RFI Payloads** - File inclusion attacks
- **Command Injection** - OS command injection

---

## ⚡ **Analysis & Forensics Toolkit**

### Digital Forensics
- **Hex/ASCII Viewer** - Binary file analysis
- **String Extractor** - Extract readable strings
- **File Signature Analyzer** - Identify file types

### Network Analysis
- **IP Address Analyzer** - CIDR, subnetting
- **HTTP Request Parser** - Parse HTTP traffic
- **User-Agent Parser** - Browser fingerprinting

### Code Analysis
- **Regex Pattern Tester** - Test regex patterns
- **JWT Security Analyzer** - Token security audit
- **Unicode/Encoding Analyzer** - Character encoding

### Deobfuscation
- **JavaScript Beautifier** - Format minified code
- **Multi-Decoder** - Decode multiple formats

---

## 📋 **Tools Menu**

Top menu bar includes quick actions:
- Hash MD5 / SHA-256
- Encode/Decode Base64
- Encode/Decode URL
- Beautify/Minify JSON
- Decode JWT
- Generate Reverse Shell

**All tools work directly on editor content!**

---

## 🚀 **System Requirements**

- **OS:** Windows 10/11 (x64)
- **RAM:** 4 GB minimum (8 GB recommended)
- **Disk:** 500 MB free space
- **Display:** 1920x1080 recommended

---

## 🔒 **Privacy & Security**

- ✅ All code and data stored locally only
- ✅ No user tracking or analytics
- ✅ No external connections without permission
- ✅ Open source and transparent

---

## 📝 **License**

MIT License - Free for personal and commercial use

---

## 🆘 **Support**

For issues or questions:
- GitHub Issues: `github.com/nullsec/null-ide`
- Email: support@nullsec.com

---

**Created by NullSec** - A Hacker's Foundation

**Version:** 1.0.0
