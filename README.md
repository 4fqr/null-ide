# Null IDE

![Null IDE Banner](./null-ide.png)

**The Ultimate Dual-Mode IDE for Hackers & Developers**

> A privacy-focused Electron IDE with **DeepZero** code editor and **GalaxyMind** security/developer tools suite.

![Version](https://img.shields.io/badge/version-2.0.0-green) ![License](https://img.shields.io/badge/license-MIT-blue) ![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)

---

## 🌟 What is Null IDE?

Null IDE is a professional development environment designed for security researchers, penetration testers, and developers. It combines a powerful Monaco-based code editor with 27 built-in security testing and developer utility tools.

### Two Modes, Infinite Possibilities

- **⚡ DeepZero Mode**: Full-featured code editor powered by VS Code's Monaco engine
- **🌌 GalaxyMind Mode**: 27 professional security & developer tools at your fingertips

---

## 🚀 Quick Start

### Download & Install

1. Download the latest installer from [Releases](https://github.com/4fqr/null-ide/releases)
2. Run `Null-IDE-Setup-2.0.0.exe`
3. Launch from Start Menu or Desktop shortcut

### Development Setup

\`\`\`bash
git clone https://github.com/4fqr/null-ide.git
cd null-ide
npm install
npm run dev
\`\`\`

---

## ✨ Features

### 💻 DeepZero Code Editor

- **Monaco Editor** - The same engine that powers VS Code
- **100+ Languages** - Syntax highlighting for all major programming languages
- **IntelliSense** - Smart autocomplete and suggestions
- **Multi-Tab Editing** - Work on multiple files simultaneously
- **Integrated Terminal** - PowerShell terminal built-in
- **File Explorer** - Browse and manage project files
- **Git Integration** - Track changes and commits

### 🌌 GalaxyMind Tools (27 Total)

#### 🔐 Security & Network Tools (8)
- **API Tester** - Test REST & GraphQL APIs
- **Port Scanner** - Scan ports with service detection
- **DNS Analyzer** - Analyze DNS records and lookups
- **Subdomain Finder** - Discover subdomains
- **WHOIS Lookup** - Domain registration information
- **Header Analyzer** - Analyze HTTP security headers
- **SQL Injection Tester** - Test SQL injection vectors (educational)
- **XSS Detector** - Detect XSS vulnerabilities (educational)
- **Uptime Checker** - Monitor website availability

#### 🛠️ Developer Utilities (18)
- **Base64 Tool** - Encode/decode Base64
- **URL Tool** - Encode/decode URLs
- **Hash Generator** - Generate SHA-256, SHA-512, MD5 hashes
- **JWT Decoder** - Decode and analyze JWT tokens
- **JSON Formatter** - Format and validate JSON
- **JSON Beautifier** - Beautify and minify JSON with indent control
- **Regex Tester** - Test regular expressions with live results
- **UUID Generator** - Generate UUID v4 identifiers
- **Timestamp Converter** - Convert between timestamp formats
- **Password Generator** - Generate cryptographically secure passwords
- **Color Converter** - Convert HEX/RGB/HSL color formats
- **HTML Entity Encoder** - Encode/decode HTML entities
- **Markdown Preview** - Live markdown rendering
- **Lorem Ipsum Generator** - Generate placeholder text
- **Diff Viewer** - Compare text differences line-by-line
- **CSS Minifier** - Minify and beautify CSS
- **Slug Generator** - Generate URL-friendly slugs
- **Cron Generator** - Create cron expressions visually

### 🤖 DeepHat AI Assistant

- **Uncensored AI** - No restrictions on security research queries
- **Code Generation** - Generate code in any language
- **Security Guidance** - Get help with penetration testing
- **Privacy First** - Your conversations stay local

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+N` | New File |
| `Ctrl+O` | Open File |
| `Ctrl+S` | Save File |
| `Ctrl+W` | Close Tab |
| `Ctrl+Shift+W` | Close All Tabs |
| `Ctrl+Tab` | Next Tab |
| `Ctrl+Shift+Tab` | Previous Tab |
| `Ctrl+B` | Toggle Left Sidebar |
| `Ctrl+\`` | Toggle Terminal |
| `Ctrl+,` | Open Settings |

---

## 🔒 Privacy & Security

**Your code never leaves your machine.**

- ✅ All data stored locally
- ✅ No telemetry or tracking
- ✅ No analytics
- ✅ No user data collection
- ✅ Open source and auditable

---

## 📦 Building from Source

### Prerequisites
- Node.js 18+
- npm or yarn

### Build Commands

\`\`\`bash
# Install dependencies
npm install

# Run in development
npm run dev

# Build production
npm run build

# Create installer
npm run package
\`\`\`

---

## 🛠️ Tech Stack

- **Electron** - Desktop application framework
- **React** - UI library
- **TypeScript** - Type-safe development
- **Monaco Editor** - VS Code's editor engine
- **Zustand** - State management
- **Vite** - Fast build tool

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details

---

## 🙏 Credits

**Created by NullSec**

Made with ❤️ for hackers, by hackers.

---

## ⚠️ Disclaimer

Null IDE's security testing tools are provided for **educational and authorized testing purposes only**. Users are responsible for ensuring all usage complies with applicable laws and regulations. Unauthorized testing of systems you do not own or have explicit permission to test is illegal.

---

## 🐛 Bug Reports & Feature Requests

Found a bug or have a feature idea? [Open an issue](https://github.com/4fqr/null-ide/issues)

---

**Star ⭐ this repo if you find it useful!**

- Multi-tab workflow support

---

##  Installation

### **Windows Installer**
1. Download `Null-IDE-Installer.exe` from [Releases](https://github.com/4fqr/null-ide/releases)
2. Run the installer
3. Follow installation wizard
4. Right-click any file/folder  **"Open with Null IDE"**

### **Development Setup**
```bash
# Clone repository
git clone https://github.com/4fqr/null-ide.git
cd null-ide

# Install dependencies
npm install

# Run development server
npm run dev

# Build for production
npm run build

# Create installer
npm run package
```

---

##  Quick Start

### **Opening Files**
- **Context Menu**: Right-click any file  "Open with Null IDE"
- **Drag & Drop**: Drag files into the editor
- **File Menu**: File  Open

### **Using Tools**
1. Click **Hacking Tools** or **Utilities** in left sidebar
2. Select a tool from the category
3. Enter input (or use content from active editor tab)
4. Click "Run Tool"
5. Results appear in the output panel or editor

### **Terminal**
- Access via **Terminal** menu or sidebar
- Full PowerShell integration
- Execute commands directly in the IDE

### **AI Assistant**
- Click **DeepHat AI** in right sidebar
- Ask security research questions
- Get exploit suggestions
- Receive code assistance

---

##  Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl+O` | Open File |
| `Ctrl+S` | Save File |
| `Ctrl+Shift+P` | Command Palette |
| `Ctrl+B` | Toggle Left Sidebar |
| `Ctrl+Shift+B` | Toggle Right Sidebar |
| `Ctrl+` | Toggle Terminal |
| `Ctrl+W` | Close Tab |
| `Ctrl+Tab` | Next Tab |
| `F11` | Fullscreen |

---

##  Tools Menu (Quick Access)

Access frequently used tools from the top menu bar:

- **Hash MD5**: Generate MD5 hash of selected text
- **Hash SHA-256**: Generate SHA-256 hash
- **Encode Base64**: Encode to Base64
- **Decode Base64**: Decode from Base64
- **Encode URL**: URL-encode text
- **Decode URL**: URL-decode text
- **Beautify JSON**: Format JSON with proper indentation
- **Minify JSON**: Compress JSON (remove whitespace)
- **Decode JWT**: Decode JSON Web Tokens
- **Generate Reverse Shell**: Create reverse shell payload

---

##  Project Structure

```
null-ide/
 src/
    main/           # Electron main process
       main.ts     # IPC handlers, window management
    preload/        # Preload scripts (security bridge)
       preload.ts  # Exposed APIs to renderer
    renderer/       # React frontend
        components/ # UI components
           layout/ # TopBar, MenuBar, Sidebar
           panels/ # HackingTools, Utilities, Terminal
        store/      # Zustand state management
        App.tsx     # Main application
 build/              # Build assets (icons, installer scripts)
 dist/               # Compiled output
 release/            # Final installer output
```

---

##  Security & Privacy

### **Privacy First**
-  **No telemetry** - Zero data collection
-  **Local-only storage** - All data stays on your machine
-  **No cloud dependencies** - Works completely offline
-  **Open source** - Audit the code yourself

### **Ethical Use Warning**
 **Null IDE is designed for authorized security research, penetration testing, and educational purposes only.**

**You must:**
- Only use on systems you own or have explicit permission to test
- Comply with all applicable laws and regulations
- Respect responsible disclosure practices

**The developers are NOT responsible for misuse of this tool.**

---

##  Contributing

Contributions are welcome! Here's how:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-tool`)
3. **Commit** your changes (`git commit -m 'Add amazing tool'`)
4. **Push** to branch (`git push origin feature/amazing-tool`)
5. **Open** a Pull Request

---

##  License

**MIT License**

Copyright (c) 2026 NullSec

---

##  Known Issues

- Terminal color scheme customization limited
- Some tools require specific input formats

See [Issues](https://github.com/4fqr/null-ide/issues) for full list.

---

##  Support

- **Issues**: [GitHub Issues](https://github.com/4fqr/null-ide/issues)
- **Discussions**: [GitHub Discussions](https://github.com/4fqr/null-ide/discussions)

---

##  Built With

- [Electron](https://www.electronjs.org/) - Desktop framework
- [React](https://react.dev/) - UI library
- [TypeScript](https://www.typescriptlang.org/) - Type safety
- [Monaco Editor](https://microsoft.github.io/monaco-editor/) - Code editing
- [Zustand](https://zustand-demo.pmnd.rs/) - State management
- [Vite](https://vitejs.dev/) - Build tool
- [electron-builder](https://www.electron.build/) - Installer creation

---

<div align="center">

**Made with  by NullSec**

 *For hackers, by hackers* 

[ Download](https://github.com/4fqr/null-ide/releases) | [ Report Bug](https://github.com/4fqr/null-ide/issues)

</div>
