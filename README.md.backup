# Null IDE

![Version](https://img.shields.io/badge/version-3.2-brightgreen) ![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue) ![License](https://img.shields.io/badge/license-MIT-orange) ![Electron](https://img.shields.io/badge/electron-28.3.3-9feaf9) ![Discord](https://img.shields.io/badge/Discord-Rich%20Presence-7289da)

**The Ultimate Code Editor & Security Toolkit for Professional Hackers and Developers**

> A privacy-first, dual-mode development environment combining the power of VS Code's Monaco Editor with 44 professional security testing and developer utility tools.

---

## 🎯 Overview

Null IDE is an advanced, cross-platform development environment specifically designed for security researchers, penetration testers, and professional developers. Built with Electron and React, it seamlessly integrates a feature-rich code editor with a comprehensive suite of security and development tools—all while maintaining complete privacy with local-only data storage.

### Key Highlights

- **🚀 Dual-Mode Architecture**: Switch between Code Mode (Monaco Editor) and Utility Mode (44 tools) instantly
- **🔐 44 Security & Developer Tools**: Network scanning, web security testing, payload generation, cryptography, and more
- **🎨 8 Built-in Themes + Custom Theme Support**: Professionally designed themes with CSS-only extension system
- **🎮 Discord Rich Presence**: Show what you're working on with live Discord status integration (fixed & improved)
- **🖥️ Cross-Platform**: Windows and Linux support with native installers
- **🔒 100% Privacy-Focused**: All data stays local—zero telemetry, no tracking, no cloud connections
- **⚡ Monaco Editor**: The same powerful engine that powers Visual Studio Code
- **🤖 AI Assistant**: Integrated uncensored AI for security research and code generation

---

## 📥 Installation

### Windows

1. Download `Null-IDE-Installer.exe` from [Releases](https://github.com/4fqr/null-ide/releases)
2. Run the installer and follow the setup wizard
3. Launch from Start Menu or Desktop shortcut

### Linux

**AppImage (Universal - Recommended)**

Download `Null-IDE-3.2.0.AppImage` from [Releases](https://github.com/4fqr/null-ide/releases)

```bash
# Make executable and run
chmod +x Null-IDE-3.2.0.AppImage
./Null-IDE-3.2.0.AppImage
```

That's it! No installation required. The AppImage includes everything needed to run.

**Debian/Ubuntu (.deb)**

```bash
sudo dpkg -i null-ide_3.2.0_amd64.deb
null-ide
```

**Fedora/RHEL/CentOS (.rpm)**

```bash
sudo rpm -i null-ide-3.2.0.x86_64.rpm
null-ide
```

**Troubleshooting**:
- If AppImage shows "FUSE not found": `sudo apt install libfuse2` (Ubuntu) or `sudo dnf install fuse` (Fedora)

**Building Linux Packages**:

Linux installers must be built on Linux. On a Linux machine:

```bash
git clone https://github.com/4fqr/null-ide.git
cd null-ide
chmod +x build-linux.sh
./build-linux.sh
```

Or manually:

```bash
npm install
npm run build
npx electron-builder --linux
```

### Development Setup

```bash
# Clone repository
git clone https://github.com/4fqr/null-ide.git
cd null-ide

# Install dependencies
npm install

# Run in development mode
npm run dev

# Build for production
npm run build

# Package for Windows
npm run package

# Package for Linux (run on Linux machine)
npx electron-builder --linux
```

---

## ✨ Features

### 💻 Code Mode (Monaco Editor)

- **Syntax Highlighting**: Support for 100+ programming languages
- **IntelliSense**: Intelligent code completion and suggestions
- **Multi-Tab Editing**: Work on multiple files simultaneously with tab management
- **File Explorer**: Built-in file browser with folder navigation
- **Integrated Terminal**: Multi-terminal support with PowerShell (Windows) and Bash (Linux)
- **Editor Customization**: Font size, word wrap, minimap, and theme settings
- **Keyboard Shortcuts**: VS Code-compatible shortcuts for familiar workflows
- **Discord Rich Presence**: Show your current file and activity status on Discord

### 🛠️ Utility Mode (38 Professional Tools)

#### 🔐 Network Tools (5)
- **API Tester** - REST/GraphQL API testing with request history
- **Port Scanner** - TCP port scanning with service detection
- **DNS Analyzer** - DNS record lookup and analysis
- **Subdomain Finder** - Subdomain enumeration and discovery
- **WHOIS Lookup** - Domain registration information retrieval

#### 🌐 Web Security Tools (11)
- **Header Analyzer** - HTTP security header analysis
- **SQL Injection Tester** - SQL injection vulnerability detection
- **XSS Detector** - Cross-site scripting vulnerability scanner
- **LFI/RFI Scanner** - Local/Remote file inclusion testing
- **CSRF Tester** - Cross-site request forgery testing
- **Directory Fuzzer** - Web directory and file discovery
- **Command Injection Tester** - OS command injection vulnerability testing
- **SSRF Tester** - Server-Side Request Forgery detection with cloud metadata testing
- **XXE Tester** - XML External Entity injection detection and analysis
- **SSTI Detector** - Server-Side Template Injection across multiple engines
- **File Upload Tester** - File upload security bypass techniques analyzer

#### 💣 Payload Tools (5)
- **Reverse Shell Generator** - Multi-platform reverse shell payloads
- **Payload Encoder** - Encode payloads for WAF bypass
- **Web Shell Generator** - PHP, ASP, JSP web shell creation
- **Code Obfuscator** - JavaScript and PowerShell obfuscation
- **Shellcode Generator** - Architecture-specific shellcode generation

#### 🔐 Cryptography Tools (6)
- **Hash Cracker** - Dictionary-based hash cracking (MD5, SHA1, SHA256)
- **Hash Generator** - Generate cryptographic hashes
- **Encryption Tool** - AES-256-GCM/CBC encryption/decryption with Web Crypto API
- **JWT Cracker** - JWT token security testing
- **Base64/Hex Tool** - Encode/decode Base64 and Hex
- **Certificate Analyzer** - X.509 SSL/TLS certificate decoder and security analysis

#### 🌍 API Security Tools (4)
- **Packet Analyzer** - Network packet capture parser (tcpdump/hex)
- **HTTP Smuggling** - HTTP request smuggling payload generator (CL.TE, TE.CL, TE.TE)
- **CORS Tester** - Cross-Origin Resource Sharing vulnerability testing
- **OAuth Tester** - OAuth 2.0 security analysis with PKCE support

#### 🔑 Authentication Tools (3)
- **JWT Decoder** - JSON Web Token decoder and validator
- **Password Generator** - Cryptographically secure password generation
- **OAuth 2.0 Tester** - Complete OAuth flow security testing

#### 🧰 Developer Utilities (10)
- **JSON Formatter** - Format and validate JSON with syntax highlighting
- **Regex Tester** - Regular expression testing with live matching
- **UUID Generator** - Generate UUID v4 identifiers
- **Timestamp Converter** - Unix timestamp conversion
- **Color Converter** - HEX/RGB/HSL color format conversion
- **Markdown Preview** - Live markdown rendering with GitHub styling
- **Diff Viewer** - Side-by-side text comparison
- **CSS Minifier** - CSS minification and beautification
- **Slug Generator** - URL-friendly slug generation
- **Cron Generator** - Visual cron expression builder

### 🎨 Theme System

- **8 Built-in Professional Themes**:
  - Null Dark (default) - Ultra-minimal dark theme
  - Cyber Purple - Cyberpunk-inspired purple theme
  - Matrix Green - Classic Matrix terminal style
  - Nord - Arctic north-bluish color palette
  - Dracula - Popular Dracula theme variant
  - Tokyo Night - Clean dark blue theme
  - Gruvbox Dark - Retro warm color scheme
  - One Dark Pro - Atom-inspired theme

- **Custom Theme Support**:
  - Install custom CSS themes via Extensions modal
  - Pre-loaded template for easy theme creation
  - Export/import themes as JSON
  - All 17 CSS variables customizable

### 🤖 DeepHat AI Assistant

- **Uncensored AI Model**: No restrictions on security research queries
- **Code Generation**: Generate code in any programming language
- **Security Guidance**: Expert advice on penetration testing techniques
- **Privacy-Focused**: Conversations stored locally only
- **Context-Aware**: Understands security tools and methodologies

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | New file |
| `Ctrl+O` | Open file |
| `Ctrl+S` | Save file |
| `Ctrl+W` | Close tab |
| `Ctrl+Shift+W` | Close all tabs |
| `Ctrl+Tab` | Next tab |
| `Ctrl+Shift+Tab` | Previous tab |
| `Ctrl+B` | Toggle left sidebar |
| `Ctrl+` \` ` | Toggle terminal |
| `Ctrl+,` | Open settings |
| `Ctrl+Shift+P` | Command palette |

---

## 🏗️ Architecture

### Technology Stack

- **Frontend**: React 18.2.0 + TypeScript 5.3.3
- **Editor**: Monaco Editor 0.45.0 (@monaco-editor/react)
- **Terminal**: XTerm.js 5.3.0 with fit addon
- **State Management**: Zustand 4.4.7
- **Desktop Framework**: Electron 28.3.3
- **Build Tool**: Vite 5.0.10
- **UI**: Custom CSS with CSS variables for theming

### Project Structure

```
null-ide/
├── src/
│   ├── main/              # Electron main process
│   │   ├── main.ts        # Main entry point
│   │   └── terminalManager.ts  # Terminal IPC handler
│   ├── preload/           # Electron preload scripts
│   │   └── preload.ts     # IPC bridge
│   └── renderer/          # React frontend
│       ├── src/
│       │   ├── components/
│       │   │   ├── modes/        # DeepZero & GalaxyMind
│       │   │   ├── galaxymind/   # 38 utility tools
│       │   │   ├── layout/       # UI layout components
│       │   │   ├── panels/       # Sidebar panels
│       │   │   ├── modals/       # Settings, About, Themes
│       │   │   ├── icons/        # SVG icon components
│       │   │   └── extensions/   # Theme extension system
│       │   ├── store/            # Zustand state management
│       │   ├── styles/           # Global CSS and themes
│       │   └── utils/            # Theme manager utilities
│       └── index.html
├── dist/                  # Build output
├── release/               # Packaged installers
└── package.json
```

---

## 🔒 Privacy & Security

### Privacy Commitments

- ✅ **100% Local Data Storage**: All files, settings, and data stay on your machine
- ✅ **Zero Telemetry**: No usage tracking, analytics, or data collection
- ✅ **No Cloud Connections**: Application works completely offline
- ✅ **No Account Required**: No registration, login, or authentication
- ✅ **Open Source**: Full source code available for audit

### Security Features

- **Sandboxed Execution**: Electron security best practices enforced
- **Context Isolation**: Renderer and main processes properly isolated
- **No Remote Code Execution**: All code runs locally
- **Educational Tools**: Security testing tools for authorized penetration testing only

**⚠️ Legal Disclaimer**: Security testing tools are for authorized use only. Users are responsible for compliance with applicable laws and regulations. Unauthorized access to computer systems is illegal.

---

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### Development Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Test thoroughly on both Windows and Linux
5. Commit with descriptive messages: `git commit -m 'feat: Add amazing feature'`
6. Push to your fork: `git push origin feature/amazing-feature`
7. Open a Pull Request

### Contribution Guidelines

- Follow TypeScript and React best practices
- Maintain code style consistency with existing codebase
- Add comments for complex logic
- Test on both Windows and Linux before submitting
- Update documentation for new features
- Ensure zero compilation errors and warnings

### Areas for Contribution

- 🐛 Bug fixes and performance improvements
- ✨ New utility tools for GalaxyMind mode
- 🎨 Custom theme designs
- 🌍 Internationalization (i18n)
- 📚 Documentation improvements
- 🧪 Additional test coverage

---

## 📊 Project Status

### Version 3.2 (Current)

**Release Date**: January 10, 2026

**What's New**:
- ✅ **6 New Advanced Security Tools**:
  - Command Injection Tester - OS command injection vulnerability detection
  - SSRF Tester - Server-Side Request Forgery with cloud metadata testing
  - XXE Tester - XML External Entity injection analyzer
  - SSTI Detector - Server-Side Template Injection across multiple engines (Jinja2, ERB, Smarty, etc.)
  - File Upload Tester - Security bypass techniques analyzer
  - Certificate Analyzer - X.509 SSL/TLS certificate analysis
- ✅ **Total: 44 Fully Functional Tools** (up from 38)
- ✅ **Discord RPC Enhanced** - Better error handling, retry logic, improved logging
- ✅ **Terminal Reliability Fixed** - Proper visibility-based initialization
- ✅ **Right Sidebar Resize Improved** - Better cursor feedback and user experience
- ✅ **All Tools Error-Free** - Comprehensive error handling across all tools
- ✅ **Zero Build Errors** - Clean compilation with no warnings

### Version 3.1

**Release Date**: January 10, 2026

**Features**:
- ✅ **Discord Rich Presence** - Show current file and activity on Discord
- ✅ Fixed Extensions modal z-index (no longer overlaps with sidebar)
- ✅ Improved terminal initialization reliability
- ✅ Enhanced right sidebar AI chat resize functionality
- ✅ Better Linux support documentation
- ✅ Updated installers for Windows and Linux

### Version 3.0

**Release Date**: January 10, 2026

**Features**:
- ✅ 9 new advanced security tools (Encryption, Packet Analyzer, HTTP Smuggling, CORS, OAuth)
- ✅ Complete theme extension system with 8 built-in themes
- ✅ Modal-based Extensions UI (centered popup)
- ✅ Back navigation buttons in all utility tools
- ✅ Terminal initialization fixes for improved stability
- ✅ Linux support (AppImage, DEB, RPM)
- ✅ Professional README and documentation

**Known Issues**:
- None currently reported

### Roadmap

- [ ] macOS support (DMG installer)
- [ ] Plugin system for community extensions
- [ ] Collaborative editing features
- [ ] Built-in Git client UI
- [ ] Package manager integration
- [ ] Debugging capabilities
- [ ] Project templates
- [ ] Code snippets library

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

### MIT License Summary

✅ Commercial use  
✅ Modification  
✅ Distribution  
✅ Private use  
❌ Liability  
❌ Warranty  

---

## 🙏 Acknowledgments

- **Monaco Editor** - The world-class code editor from Microsoft
- **XTerm.js** - Full-featured terminal for the web
- **Electron** - Build cross-platform desktop apps with web technologies
- **React** - UI library for building user interfaces
- **Zustand** - Minimal state management solution
- **Vite** - Next generation frontend tooling

---

## 📞 Support

### Getting Help

- 📖 **Documentation**: Read this README and inline code comments
- 🐛 **Bug Reports**: [Open an issue](https://github.com/4fqr/null-ide/issues) on GitHub
- 💡 **Feature Requests**: [Submit an idea](https://github.com/4fqr/null-ide/issues) with the `enhancement` label
- 💬 **Discussions**: Use GitHub Discussions for questions and community chat

### Links

- **Repository**: [https://github.com/4fqr/null-ide](https://github.com/4fqr/null-ide)
- **Releases**: [https://github.com/4fqr/null-ide/releases](https://github.com/4fqr/null-ide/releases)
- **Issues**: [https://github.com/4fqr/null-ide/issues](https://github.com/4fqr/null-ide/issues)

---

## 🌟 Star History

If you find Null IDE useful, please consider starring the repository! ⭐

---

**Made with ❤️ by NullSec**  
*Empowering security researchers and developers worldwide*

**Version 3.1** | January 2026
