# Null IDE - Changelog

## Version 3.5.0 (2025-02-23)

### 🚀 Major Feature Update

**DeepChat AI Integration**

- ✅ Added DeepChat AI sidebar with live connection to app.deephat.ai
- ✅ Full OAuth login support (GitHub & Google authentication)
- ✅ Webview-based integration with popup window support
- ✅ Resizable sidebar panel (300px - 800px width)
- ✅ Loading indicator and connection status
- ✅ Reload and open-in-browser buttons
- ✅ Toggle button in status bar

**Live Preview Server**

- ✅ Go Live button for instant local server on localhost:8080
- ✅ HTML files served directly with live reload
- ✅ Markdown files converted to styled HTML
- ✅ Code files rendered with syntax highlighting (highlight.js)
- ✅ "Port opened: 8080" status message
- ✅ Open in Browser button when live
- ✅ Works even with no file open (placeholder page)

**UI/UX Improvements**

- ✅ Enhanced status bar with live server and AI indicators
- ✅ Glowing animations for active states
- ✅ Better visual feedback for user actions
- ✅ Improved keyboard shortcuts handling

**Technical**

- ✅ Enabled webviewTag in Electron for OAuth support
- ✅ Added LiveAPI TypeScript definitions
- ✅ Improved error handling throughout

---

## Version 3.4.0 (2025-02-22)

### 🎯 Flatpak & Security Tools Update

**Flatpak Support**

- ✅ Complete Flatpak support for all Linux distributions
- ✅ Build scripts for Flatpak bundle creation
- ✅ Metainfo XML with release notes

**Security Tools**

- ✅ Improved SQL injection detection algorithms
- ✅ Enhanced JWT analyzer with algorithm confusion detection
- ✅ New GraphQL introspection scanner
- ✅ Better serial/USB device detection

**Performance**

- ✅ Performance improvements for large files
- ✅ Better memory management

---

## Version 3.3.0 (2025-01-15)

### 🔐 Security Tools Expansion

**New Tools**

- ✅ Race condition detector
- ✅ Cache poisoning testing tool
- ✅ DNS rebinding attack module

**Improvements**

- ✅ Better tool categorization
- ✅ Enhanced result display

---

## Version 3.2.0 (2024-12-01)

### ⚡ Stability Release

- ✅ Stability and performance improvements
- ✅ Bug fixes and minor UI polish

---

## Version 3.0.0 (2024-11-01)

### 🎉 Major Rewrite

**Core Architecture**

- ✅ Migrated to Electron 35.x
- ✅ React 18 with TypeScript strict mode
- ✅ Vite for fast builds
- ✅ Zustand for state management

**Terminal**

- ✅ Built-in terminal with node-pty support
- ✅ Real bash/zsh/powershell integration
- ✅ Multiple terminal instances

**Security Tools (80+ tools)**

- ✅ Network Security (Port Scanner, DNS Analyzer, etc.)
- ✅ Web Security (SQLi, XSS, SSRF, XXE, etc.)
- ✅ Authentication Tools (JWT, OAuth, SAML)
- ✅ Cloud Security (Docker, K8s, S3, etc.)
- ✅ Cryptography Tools
- ✅ Payload Generators

---

## Version 1.0.0 (2024-01-01)

### 🎉 Initial Release

**Core Features**

- ✅ Complete Electron + React + TypeScript desktop application
- ✅ Monaco Editor integration with full syntax highlighting
- ✅ Multi-tab file editing support
- ✅ Dark hacker-themed UI with smooth animations
- ✅ Privacy-first architecture with local-only storage

**Left Sidebar - Swiss Army Knife**

- ✅ File Explorer with folder browsing
- ✅ 100+ Hacking & Security Tools
  - Network scanning (port scanner, DNS lookup, reverse DNS)
  - Cryptography & hashing (MD5, SHA-1, SHA-256, SHA-512)
  - Encoding/decoding (Base64, URL, Hex, Binary, HTML)
  - Web & HTTP tools (headers, status codes, user agent)
  - Security analysis (password strength, JWT decoder, patterns)
  - System & network info
- ✅ 1000+ Programmer Utilities
  - 50+ text case conversions
  - 100+ text transformations & filters
  - 100+ number & math conversions
  - 50+ date & time utilities
  - 100+ JSON & data tools
  - 200+ code generators (React, Express, functions, classes)
  - 50+ regex & pattern tools
  - 100+ random generators

**Right Sidebar**

- ✅ Embedded DeepHat AI browser (https://deephat.ai)
- ✅ Reload and control buttons
- ✅ Show/hide toggle

**Settings & Configuration**

- ✅ General settings (auto-save, UI preferences)
- ✅ Privacy settings with clear statements
- ✅ Editor preferences (font size, tab size, word wrap, minimap)
- ✅ Persistent configuration storage

**UI Components**

- ✅ Top bar with branding, tabs, and controls
- ✅ Status bar with privacy indicator and app info
- ✅ About modal with NullSec branding
- ✅ Smooth animations and transitions throughout

**Technical**

- ✅ TypeScript strict mode enabled
- ✅ ESLint and Prettier configuration
- ✅ Vite for fast development and building
- ✅ Electron IPC for secure communication
- ✅ Zustand for state management
- ✅ CSS variables for consistent theming

**Documentation**

- ✅ Comprehensive README with architecture details
- ✅ Quick setup guide
- ✅ Code comments throughout
- ✅ Tool descriptions for all utilities

**Privacy & Security**

- ✅ All data stored locally only
- ✅ No telemetry or tracking (disabled by default)
- ✅ Context isolation for security
- ✅ Secure IPC between processes
- ✅ Clear privacy statements

**Known Limitations**

- Some tools are placeholders awaiting external service integration (e.g., WHOIS)
- File tree navigation is single-level (no recursive directory walking yet)
- DeepHat browser view requires internet connection
- No built-in terminal yet

### Coming Soon (Planned Features)

- 🔜 Built-in terminal emulator
- 🔜 Git integration
- 🔜 Plugin system for extensions
- 🔜 More file operations (create, delete, rename)
- 🔜 Recursive directory explorer
- 🔜 Search in files
- 🔜 Command palette
- 🔜 More language servers for IntelliSense
- 🔜 Themes customization UI
- 🔜 Export tool outputs to files

---

## Future Roadmap

### Version 1.1.0 (Planned)

- Terminal integration
- Git support
- Search in project
- Command palette (Ctrl+Shift+P)

### Version 1.2.0 (Planned)

- Plugin API
- Theme marketplace
- More advanced code generators
- Snippet management

### Version 2.0.0 (Future)

- AI code completion
- Collaborative editing
- Cloud sync (optional)
- Mobile companion app

---

## Contributing

We welcome contributions! See the main README for details on how to add new tools and features.

---

© 2026 NullSec. All rights reserved.
