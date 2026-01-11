# Null IDE – The Ultimate Hacker's Code Editor & Security Toolkit

<div align="center">

**🔥 Cross-Platform IDE with 49+ Security Tools + Discord RPC 🔥**

[![Version](https://img.shields.io/badge/version-3.3.8-00ffaa.svg)](https://github.com/4fqr/null-ide/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)]()
[![Electron](https://img.shields.io/badge/electron-28.3.3-47848f.svg)](https://www.electronjs.org/)

</div>

---

## 🚀 Overview

**Null IDE** is a powerful, feature-rich code editor built specifically for security researchers, penetration testers, and developers who need integrated hacking tools alongside their development environment.

### Why Null IDE?

- **🛠️ 49+ Security Tools** - From port scanners to XSS detectors, all in one place
- **💻 Full-Featured IDE** - Monaco Editor (VSCode engine) with 50+ language support  
- **🔌 Dual Mode** - Switch between Code Mode (development) & Utility Mode (security tools)
- **🤖 AI Assistant** - Integrated DeepHat AI for code help
- **🎮 Discord RPC** - Show your activity in Discord
- **⚡ Fast & Responsive** - Built with Electron, React, TypeScript

---

## 📥 Installation

### 🪟 Windows

**Download**: [`Null-IDE-Installer.exe`](https://github.com/4fqr/null-ide/releases) (90.8 MB)

**Install**:
```cmd
Null-IDE-Installer.exe
```
Follow wizard → Launch from Start Menu

**Features**: PowerShell terminal, Discord RPC, All 49+ tools, File creation, Save All

---

### 🐧 Linux

**Method 1: Build from Source** (Recommended)

```bash
# Prerequisites
sudo apt install nodejs npm git  # Ubuntu/Debian
# OR
sudo dnf install nodejs npm git  # Fedora/RHEL

# Clone & build
git clone https://github.com/4fqr/null-ide.git
cd null-ide
npm install
npm run build
npx electron-builder --linux
```

**Outputs**:
- `Null IDE-3.3.7.AppImage` - Universal (all distros)
- `null-ide_3.3.7_amd64.deb` - Debian/Ubuntu/Mint
- `null-ide-3.3.7.x86_64.rpm` - Fedora/RHEL/CentOS

**Install Options**:

**Ubuntu/Debian (.deb)**:
```bash
sudo dpkg -i null-ide_3.3.7_amd64.deb
sudo apt-get install -f  # Fix dependencies
null-ide
```

**Fedora/RHEL (.rpm)**:
```bash
sudo dnf install null-ide-3.3.7.x86_64.rpm
null-ide
```

**AppImage (Universal)**:
```bash
chmod +x "Null IDE-3.3.7.AppImage"
./"Null IDE-3.3.7.AppImage"
```

**Arch Linux**:
```bash
git clone https://github.com/4fqr/null-ide.git
cd null-ide
makepkg -si
```

**NixOS**:
```bash
nix-shell -p nodejs electron
npm install && npm run build
npx electron-builder --linux appimage
./"Null IDE-3.3.7.AppImage"
```

**Features**: Bash/Zsh terminal (auto-detect), Discord RPC, All tools, Cross-platform

---

### 🍎 macOS

```bash
# Install dependencies
brew install node

# Build
git clone https://github.com/4fqr/null-ide.git
cd null-ide
npm install
npm run build
npx electron-builder --mac
```

Open `Null IDE-3.3.7.dmg` → Drag to Applications

**Features**: Zsh terminal, Discord RPC, Native macOS UI

---

## 🛠️ 49+ Security Tools

### Network Security
- Port Scanner, DNS Analyzer, WHOIS Lookup, Subdomain Finder
- Uptime Checker, IP Geolocation, Traceroute, Reverse DNS

### Web Security
- XSS Detector, SQL Injection Tester, Command Injection Tester
- SSRF Tester, Directory Fuzzer, LFI Scanner, CORS Tester
- XXE Tester, SSTI Detector, OAuth Tester, Header Analyzer
- File Upload Tester, HTTP Smuggling, Packet Analyzer

### Crypto & Encoding
- Hash Calculator (MD5, SHA-1, SHA-256, SHA-512)
- Base64, JWT Decoder, URL Encoder/Decoder
- Hex Converter, Caesar Cipher, ROT13

### Developer Utilities
- UUID Generator, Timestamp Converter, JSON Formatter
- Regex Tester, Code Obfuscator, Color Picker
- Lorem Ipsum, Diff Checker, SSL Certificate Viewer

---

## 🔧 Building from Source

### Prerequisites
- Node.js 18+
- npm
- Git

### Setup
```bash
git clone https://github.com/4fqr/null-ide.git
cd null-ide
npm install
```

### Development
```bash
npm run dev
```

### Build Installers
```bash
# Windows only (on Windows)
npm run package:win

# Linux only (on Linux) - generates .deb, .rpm, .AppImage
npm run package:linux

# Current platform
npm run package

# All platforms (requires respective OS or CI/CD)
npm run package:all
```

---

## 🎮 Discord Rich Presence

### Setup
1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Use application ID: `1459478156120428606`
3. Upload assets to **Rich Presence** → **Art Assets**:
   - `nullide` - Main logo (512x512)
   - `code` - Coding icon (512x512)
   - `idle` - Idle icon (512x512)
4. Restart Null IDE

RPC will show:
- Current file being edited
- "Hacking & Programming" when idle
- Auto-updates on file changes

  RPC Should already be working, If not, download the source code and do the steps above.

---

## ⌨️ Keyboard Shortcuts

| Action | Shortcut |
|--------|----------|
| Save File | `Ctrl+S` |
| Close Tab | `Ctrl+W` |
| Close All | `Ctrl+Shift+W` |
| Next Tab | `Ctrl+Tab` |
| Previous Tab | `Ctrl+Shift+Tab` |
| Toggle Left Sidebar | `Ctrl+B` |
| Toggle Right Sidebar | `Ctrl+Shift+B` |
| Toggle Terminal | `` Ctrl+` `` |
| Settings | `Ctrl+,` |

---

## 🏗️ Tech Stack

- **Frontend**: React 18, TypeScript 5, Monaco Editor, Zustand, XTerm.js
- **Backend**: Electron 28.3.3, Node.js, discord-rpc 4.0.1
- **Build**: Vite 5, electron-builder 24

---

## 🐛 Troubleshooting

### Terminal Won't Resize
**Fixed in v3.2.9!** Terminal now properly resizes both up and down (50px-800px range). Added `flex-shrink: 0` to prevent compression.

### Linux Installers Missing from Releases
Linux installers (.deb, .rpm, .AppImage) must be built on Linux. Use GitHub Actions or build manually:
```bash
npm run package:linux
```

### Discord RPC Not Showing
1. Make sure Discord is running
2. Upload 3 assets to Discord Developer Portal (`nullide`, `code`, `idle`)
3. Restart Null IDE

### Resize Handles Hard to Grab
v3.2.7+ has invisible 25-30px wide handles:
- **Terminal**: Top edge (25px tall)
- **Right Sidebar**: Left edge (30px wide)

---

## 📜 License

MIT License - Copyright (c) 2026 NullSec

---

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes and test
4. Submit Pull Request

---

<div align="center">

Made with 💀 by [NullSec](https://github.com/4fqr)

[⬆ Back to Top](#null-ide--the-ultimate-hackers-code-editor--security-toolkit)

</div>
