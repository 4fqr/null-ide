# Null IDE

**Cross-Platform Security-Focused Code Editor**

[![Version](https://img.shields.io/badge/version-3.4.0-00ffaa.svg)](https://github.com/4fqr/null-ide/releases)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)]()
[![Electron](https://img.shields.io/badge/electron-35.7.5-47848f.svg)](https://www.electronjs.org/)

---

## Overview

Null IDE is a code editor designed for security researchers, penetration testers, and software developers. It integrates 120+ security tools with a full-featured development environment.

### Key Features

- **120+ Security Tools** - Network scanning, web security testing, cryptography utilities
- **Monaco Editor** - VS Code editing engine with 112 language support
- **Dual Mode Interface** - Code mode for development, Utility mode for security tools
- **Integrated Terminal** - Multi-tab terminal with bash/zsh/powershell support
- **Discord Rich Presence** - Activity display integration
- **Cross-Platform** - Windows, Linux, macOS support
- **VS Code-like File Explorer** - Create files/folders, rename, delete, context menu

---

## Installation

### Windows

Download and run the installer from [Releases](https://github.com/4fqr/null-ide/releases).

```cmd
Null-IDE-Installer.exe
```

### Linux

#### Option 1: AppImage (Easiest)

Download from [Releases](https://github.com/4fqr/null-ide/releases):

```bash
chmod +x Null-IDE-3.4.0.AppImage
./Null-IDE-3.4.0.AppImage
```

#### Option 2: DEB Package (Debian/Ubuntu/Mint)

```bash
# Download from Releases, then:
sudo dpkg -i null-ide_3.4.0_amd64.deb
sudo apt-get install -f  # Fix dependencies if needed
null-ide
```

#### Option 3: RPM Package (Fedora/RHEL/CentOS)

```bash
# Download from Releases, then:
sudo dnf install null-ide-3.4.0.x86_64.rpm
null-ide
```

#### Option 4: Snap Package

```bash
# Download from Releases, then:
sudo snap install --dangerous null-ide_3.4.0_amd64.snap --classic
null-ide
```

#### Option 5: Flatpak (Build from Source)

**Prerequisites:**

```bash
# Ubuntu/Debian
sudo apt install flatpak flatpak-builder

# Fedora
sudo dnf install flatpak flatpak-builder

# Arch
sudo pacman -S flatpak flatpak-builder
```

**Build and Install:**

```bash
# Clone the repository
git clone https://github.com/4fqr/null-ide.git
cd null-ide

# Install dependencies
npm install

# Build the application
npm run build

# Build and install Flatpak (one command)
bash scripts/build-flatpak.sh install

# Run the installed Flatpak
flatpak run com.nullide.app
```

**Create Distributable Bundle:**

```bash
# Build and create a .flatpak bundle file
bash scripts/build-flatpak.sh bundle

# This creates: Null-IDE-3.4.0.flatpak
# Share this file, others can install with:
flatpak install --user Null-IDE-3.4.0.flatpak
```

**Full Build (all steps):**

```bash
bash scripts/build-flatpak.sh all
```

**Available Flatpak Build Commands:**
| Command | Description |
|---------|-------------|
| `bash scripts/build-flatpak.sh build` | Build Flatpak only |
| `bash scripts/build-flatpak.sh install` | Build and install locally |
| `bash scripts/build-flatpak.sh bundle` | Create distributable .flatpak file |
| `bash scripts/build-flatpak.sh run` | Run installed Flatpak |
| `bash scripts/build-flatpak.sh all` | Complete build process |
| `bash scripts/build-flatpak.sh deps` | Install dependencies only |

### macOS

```bash
brew install node
git clone https://github.com/4fqr/null-ide.git
cd null-ide
npm install
npm run build
npx electron-builder --mac
```

Open `Null IDE-3.4.0.dmg` and drag to Applications.

---

## Security Tools

### Network Security

| Tool             | Description                                       |
| ---------------- | ------------------------------------------------- |
| Port Scanner     | TCP/UDP port scanning with service detection      |
| DNS Analyzer     | DNS enumeration and zone transfer testing         |
| Subdomain Finder | Subdomain discovery and attack surface mapping    |
| WHOIS Lookup     | Domain registration and reconnaissance data       |
| Reverse DNS      | IP to domain resolution                           |
| BGP Scanner      | BGP route hijacking detection                     |
| ARP Scanner      | ARP spoofing attack analysis                      |
| VNC Scanner      | VNC authentication bypass testing                 |
| RDP Scanner      | RDP vulnerability detection                       |
| FTP Scanner      | FTP anonymous access testing                      |
| SMB Scanner      | SMB share enumeration and vulnerability detection |
| SNMP Scanner     | SNMP community string testing                     |
| LDAP Scanner     | LDAP/AD anonymous bind testing                    |

### Web Security

| Tool                    | Description                                |
| ----------------------- | ------------------------------------------ |
| SQL Injection Tester    | Automated SQL injection detection          |
| XSS Detector            | Cross-site scripting vulnerability scanner |
| SSRF Tester             | Server-side request forgery testing        |
| XXE Tester              | XML external entity injection              |
| SSTI Detector           | Server-side template injection             |
| LFI/RFI Scanner         | Local/remote file inclusion testing        |
| CSRF Tester             | Cross-site request forgery testing         |
| Command Injection       | OS command injection testing               |
| Open Redirect Scanner   | Open redirect vulnerability detection      |
| Clickjacking Tester     | X-Frame-Options and CSP testing            |
| Cookie Analyzer         | Cookie security flags analysis             |
| Header Analyzer         | HTTP security headers analysis             |
| IDOR Tester             | Insecure direct object reference testing   |
| Path Traversal          | Directory traversal vulnerability scanner  |
| CRLF Injection          | HTTP response splitting testing            |
| DOM XSS Scanner         | DOM-based XSS analysis                     |
| CSP Bypass              | Content Security Policy analyzer           |
| HSTS Checker            | HSTS validation and preload status         |
| HTTP Method Tester      | Dangerous HTTP method testing              |
| Host Header Injection   | Host header attack testing                 |
| Cache Poisoning         | Web cache poisoning scanner                |
| Race Condition Tester   | Concurrent request vulnerability testing   |
| Deserialization Scanner | Unsafe deserialization detection           |
| Prototype Pollution     | JavaScript prototype pollution testing     |
| WebSocket Security      | WebSocket security testing                 |
| HTTP/2 Scanner          | HTTP/2 vulnerability detection             |

### Authentication & API Security

| Tool                    | Description                            |
| ----------------------- | -------------------------------------- |
| JWT Decoder             | JWT token analysis                     |
| JWT Cracker             | Weak JWT secret brute forcing          |
| JWT Algorithm Confusion | JWT algorithm confusion attack testing |
| JWT Weak Secret         | JWT secret strength analysis           |
| OAuth Tester            | OAuth flow testing                     |
| OAuth 2.0 Scanner       | OAuth 2.0 security flaw detection      |
| SAML Scanner            | SAML assertion validation              |
| Authentication Bypass   | Auth bypass vulnerability testing      |
| Authorization Bypass    | IDOR and path traversal testing        |
| Session Management      | Session security analysis              |
| API Key Scanner         | Exposed API key detection              |
| API Rate Limit Tester   | Rate limiting protection testing       |
| GraphQL Scanner         | GraphQL introspection and security     |
| Password Policy Checker | Password strength analysis             |

### Cloud & Infrastructure

| Tool                  | Description                                  |
| --------------------- | -------------------------------------------- |
| Cloud Metadata        | AWS/Azure/GCP metadata endpoint testing      |
| S3 Scanner            | S3 bucket permission testing                 |
| Docker Scanner        | Exposed Docker API detection                 |
| Kubernetes Scanner    | K8s API unauthorized access testing          |
| Redis Scanner         | Redis unauthorized access testing            |
| MongoDB Scanner       | MongoDB authentication bypass testing        |
| Elasticsearch Scanner | Elasticsearch exposure detection             |
| Memcached Scanner     | Memcached exposure and amplification testing |
| etcd Scanner          | etcd key-value store exposure                |
| Consul Scanner        | Consul API exposure testing                  |

### Cryptography

| Tool                   | Description                             |
| ---------------------- | --------------------------------------- |
| Hash Generator         | MD5, SHA-1, SHA-256, SHA-512 generation |
| Hash Cracker           | Hash dictionary attack                  |
| Cipher ID              | Encryption algorithm identification     |
| RSA Analyzer           | RSA key strength analysis               |
| Padding Oracle         | Padding oracle attack testing           |
| Hash Extension         | Hash length extension attack            |
| Crypto Address         | Cryptocurrency address validation       |
| Steganography Detector | Hidden data detection in images         |
| Randomness Analyzer    | PRNG quality testing                    |

### Encoding & Utilities

| Tool                   | Description                    |
| ---------------------- | ------------------------------ |
| Base64 Encoder/Decoder | Base64 encoding and decoding   |
| URL Encoder/Decoder    | URL encoding and decoding      |
| HTML Entity Encoder    | HTML entity encoding           |
| JSON Formatter         | JSON formatting and validation |
| Regex Tester           | Regular expression testing     |
| UUID Generator         | UUID/GUID generation           |
| Timestamp Converter    | Unix/ISO timestamp conversion  |
| Color Converter        | HEX/RGB/HSL conversion         |
| Diff Viewer            | Text comparison tool           |
| Markdown Preview       | Live markdown rendering        |
| Lorem Ipsum Generator  | Placeholder text generation    |
| Slug Generator         | URL slug generation            |
| Cron Generator         | Cron expression builder        |

### Payload Generation

| Tool                    | Description                           |
| ----------------------- | ------------------------------------- |
| Reverse Shell Generator | Multi-language reverse shell payloads |
| Web Shell Generator     | PHP/ASP/JSP web shells                |
| Code Obfuscator         | JavaScript/PowerShell obfuscation     |

---

## Supported Languages

Null IDE supports syntax highlighting for 112 programming languages including:

**Mainstream**: JavaScript, TypeScript, Python, Java, C, C++, C#, Go, Rust, PHP, Ruby, Swift, Kotlin, Scala, Perl, Lua, R, SQL

**Web**: HTML, CSS, SCSS, SASS, LESS, XML, JSON, YAML, Markdown

**Systems**: Assembly (x86, x64, ARM), Rust, Zig, V, Odin, Nim

**Functional**: Haskell, OCaml, F#, Elm, PureScript, Idris, Clojure, Scheme, Racket, Erlang, Elixir

**Niche**: Fortran, COBOL, Pascal, Ada, Julia, Dart, Groovy, Prolog, Forth, APL, Solidity, Move, Cairo, Carbon, Mojo, and 60+ more.

---

## Building from Source

### Prerequisites

- Node.js 18+
- npm
- Git

### Quick Start

```bash
git clone https://github.com/4fqr/null-ide.git
cd null-ide
npm install
npm run build
npm run dev
```

### Build Commands

| Command                 | Description                               |
| ----------------------- | ----------------------------------------- |
| `npm run dev`           | Start development server                  |
| `npm run build`         | Build for production                      |
| `npm run package`       | Package for current platform              |
| `npm run package:win`   | Package Windows installer                 |
| `npm run package:linux` | Package AppImage, DEB, RPM, Snap, Flatpak |
| `npm run package:mac`   | Package macOS DMG                         |
| `npm run package:all`   | Package for all platforms                 |

---

## Keyboard Shortcuts

| Action               | Shortcut       |
| -------------------- | -------------- |
| Save File            | Ctrl+S         |
| Close Tab            | Ctrl+W         |
| Close All Tabs       | Ctrl+Shift+W   |
| Next Tab             | Ctrl+Tab       |
| Previous Tab         | Ctrl+Shift+Tab |
| Toggle Left Sidebar  | Ctrl+B         |
| Toggle Right Sidebar | Ctrl+Shift+B   |
| Toggle Terminal      | Ctrl+`         |
| Settings             | Ctrl+,         |

---

## Tech Stack

- **Frontend**: React 18, TypeScript 5, Monaco Editor, Zustand, XTerm.js
- **Backend**: Electron 35.7.5, Node.js
- **Build**: Vite 6, electron-builder 26

---

## Discord Rich Presence

1. Go to [Discord Developer Portal](https://discord.com/developers/applications)
2. Application ID: `1459478156120428606`
3. Upload assets: `nullide`, `code`, `idle` (512x512 each)
4. Restart Null IDE

---

## License

MIT License - Copyright (c) 2026 NullSec

---

## Contributing

1. Fork the repository
2. Create feature branch
3. Make changes and test
4. Submit Pull Request

---

## Support

Report issues at [GitHub Issues](https://github.com/4fqr/null-ide/issues)
