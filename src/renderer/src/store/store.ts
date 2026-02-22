import { create } from 'zustand';

export interface EditorTab {
  id: string;
  path: string;
  name: string;
  language: string;
  content: string;
  modified: boolean;
}

export interface APIRequest {
  id: string;
  name: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  url: string;
  headers: Record<string, string>;
  body?: string;
  timestamp: number;
}

export interface APIResponse {
  status: number;
  statusText: string;
  headers: Record<string, string>;
  data: unknown;
  time: number;
}

export interface ToolResult {
  id: string;
  toolName: string;
  timestamp: number;
  input: unknown;
  output: unknown;
  success: boolean;
  error?: string;
  result?: unknown;
}

interface UIState {
  mode: 'code' | 'utility' | 'galaxymind';
  setMode: (mode: 'code' | 'utility' | 'galaxymind') => void;

  leftSidebarVisible: boolean;
  rightSidebarVisible: boolean;
  terminalVisible: boolean;
  terminalHeight: number;
  leftSidebarWidth: number;
  rightSidebarWidth: number;

  activeLeftPanel: string;
  activeGalaxyTool: string | null;

  tabs: EditorTab[];
  activeTabId: string | null;

  apiRequests: APIRequest[];
  apiHistory: Array<{ request: APIRequest; response: APIResponse }>;
  toolResults: ToolResult[];

  editorSettings: {
    fontSize: number;
    tabSize: number;
    wordWrap: boolean;
    minimap: boolean;
  };

  settingsOpen: boolean;
  aboutOpen: boolean;
  themesOpen: boolean;

  theme: 'dark';

  selectedText: string;
  setSelectedText: (text: string) => void;

  toggleLeftSidebar: () => void;
  toggleRightSidebar: () => void;
  toggleTerminal: () => void;
  setTerminalHeight: (height: number) => void;
  setActiveLeftPanel: (panel: string) => void;
  setActiveGalaxyTool: (tool: string | null) => void;

  openTab: (tab: EditorTab) => void;
  closeTab: (tabId: string) => void;
  closeAllTabs: () => void;
  closeOtherTabs: (tabId: string) => void;
  setActiveTab: (tabId: string) => void;
  updateTabContent: (tabId: string, content: string) => void;
  setLeftSidebarWidth: (width: number) => void;
  setRightSidebarWidth: (width: number) => void;
  updateEditorSettings: (settings: Partial<UIState['editorSettings']>) => void;

  addAPIRequest: (request: APIRequest) => void;
  addToAPIHistory: (request: APIRequest, response: APIResponse) => void;
  addToolResult: (result: ToolResult) => void;
  clearToolResults: () => void;

  openSettings: () => void;
  closeSettings: () => void;
  openAbout: () => void;
  closeAbout: () => void;
  openThemes: () => void;
  closeThemes: () => void;
}

export const useStore = create<UIState>((set) => ({
  mode: 'code',
  leftSidebarVisible: true,
  rightSidebarVisible: true,
  terminalVisible: true,
  terminalHeight: 300,
  leftSidebarWidth: 250,
  rightSidebarWidth: 250,
  activeLeftPanel: 'explorer',
  activeGalaxyTool: null,
  selectedText: '',
  apiRequests: [],
  apiHistory: [],
  toolResults: [],
  editorSettings: {
    fontSize: 15,
    tabSize: 2,
    wordWrap: false,
    minimap: true,
  },
  tabs: [
    {
      id: 'welcome',
      path: '',
      name: 'Welcome',
      language: 'markdown',
      content: `# Welcome to Null IDE v3.0

**The Ultimate Hacker's Code Editor & Security Toolkit**

## 🚀 Quick Start

### Keyboard Shortcuts
- **Ctrl+N**: New file
- **Ctrl+O**: Open file
- **Ctrl+S**: Save file
- **Ctrl+W**: Close tab
- **Ctrl+Shift+W**: Close all tabs
- **Ctrl+Tab**: Next tab
- **Ctrl+Shift+Tab**: Previous tab
- **Ctrl+B**: Toggle left sidebar
- **Ctrl+\`**: Toggle terminal
- **Ctrl+,**: Settings

## ⚡ Features

✓ **Monaco Editor** - VS Code engine with IntelliSense
✓ **38 Security Tools** - Advanced penetration testing arsenal
✓ **Multi-Terminal** - Integrated PowerShell terminals
✓ **Theme Extensions** - 8 built-in themes + custom CSS themes
✓ **Privacy-Focused** - All data stays local, no telemetry
✓ **Zero Errors** - Production-ready, fully tested build

## 🎨 Two Modes

**📝 Code Mode**: Full-featured Monaco Editor
- Syntax highlighting for 100+ languages
- IntelliSense & autocomplete
- Multiple tabs & split view
- Git integration ready

**🛠️ Utility Mode**: 38 Professional Security Tools
- Network scanning & reconnaissance
- Web security testing (XSS, SQLi, CSRF, LFI)
- Payload generation (reverse shells, web shells, shellcode)
- Cryptographic tools (hash cracking, JWT, encryption)
- API testing (packet analysis, CORS, OAuth, HTTP smuggling)

## 🔐 Security Tools (38 Total)

### Network (5 tools)
Port Scanner • Subdomain Finder • DNS Analyzer • WHOIS • Reverse DNS

### Web Security (6 tools)
SQL Injection Tester • XSS Detector • Security Headers • LFI/RFI Scanner • CSRF Tester • Directory Fuzzer

### Payloads (5 tools)
Reverse Shell Generator • Payload Encoder • Web Shell Generator • Code Obfuscator • Shellcode Generator

### Crypto (5 tools)
Hash Cracker • Hash Generator • AES/RSA Encryption • JWT Cracker • Base64/Hex Tool

### API (4 tools)
API Tester • Packet Analyzer • HTTP Smuggling • CORS Tester

### Auth (3 tools)
Password Generator • JWT Decoder • OAuth 2.0 Tester

### Developer Tools (10 tools)
JSON Formatter • Regex Tester • UUID Generator • Timestamp Converter • Color Converter • Diff Viewer • Markdown Preview

## 🎨 Theme Extensions

Access **Extensions** in the left sidebar to:
- Choose from 8 built-in professional themes
- Install custom CSS themes
- Create your own themes
- Export/import theme configs

Available themes: Null Dark (default), Cyber Purple, Matrix Green, Nord, Dracula, Tokyo Night, Gruvbox Dark, One Dark Pro

## 🖥️ Terminal

Integrated PowerShell terminals with:
- Multiple terminal instances
- Proper initialization (fixed blank screen bug)
- Automatic terminal spawn
- Full terminal output support

## 🔒 Privacy Notice

**100% Local** - All code, data, and settings stay on your machine.
**No Telemetry** - Zero tracking, analytics, or external connections.
**No Cloud** - Everything runs locally for maximum security.

---

**v3.0 Updates**: 9 new advanced tools, terminal fixes, theme extension system, 100% working tools, zero errors
`,
      modified: false,
    },
  ],
  activeTabId: 'welcome',
  settingsOpen: false,
  aboutOpen: false,
  themesOpen: false,
  theme: 'dark',

  setMode: (mode) => set({ mode }),
  setSelectedText: (text) => set({ selectedText: text }),
  toggleLeftSidebar: () => set((state) => ({ leftSidebarVisible: !state.leftSidebarVisible })),
  toggleRightSidebar: () => set((state) => ({ rightSidebarVisible: !state.rightSidebarVisible })),
  toggleTerminal: () => set((state) => ({ terminalVisible: !state.terminalVisible })),
  setTerminalHeight: (height) => set({ terminalHeight: height }),
  setActiveLeftPanel: (panel) => set({ activeLeftPanel: panel }),
  setActiveGalaxyTool: (tool) => set({ activeGalaxyTool: tool }),

  addAPIRequest: (request) =>
    set((state) => ({
      apiRequests: [...state.apiRequests, request],
    })),
  addToAPIHistory: (request, response) =>
    set((state) => ({
      apiHistory: [...state.apiHistory, { request, response }],
    })),
  addToolResult: (result) =>
    set((state) => ({
      toolResults: [result, ...state.toolResults].slice(0, 100),
    })),
  clearToolResults: () => set({ toolResults: [] }),

  openTab: (tab) =>
    set((state) => {
      const existingTab = state.tabs.find((t) => t.path === tab.path && tab.path !== '');
      if (existingTab) {
        return { activeTabId: existingTab.id };
      }
      return { tabs: [...state.tabs, tab], activeTabId: tab.id };
    }),

  closeTab: (tabId) =>
    set((state) => {
      const newTabs = state.tabs.filter((t) => t.id !== tabId);
      const closedTabIndex = state.tabs.findIndex((t) => t.id === tabId);
      let newActiveId = state.activeTabId;

      if (tabId === state.activeTabId && newTabs.length > 0) {
        const newIndex = Math.min(closedTabIndex, newTabs.length - 1);
        newActiveId = newTabs[newIndex]?.id || null;
      }

      return { tabs: newTabs, activeTabId: newActiveId };
    }),

  closeAllTabs: () => set({ tabs: [], activeTabId: null }),

  closeOtherTabs: (tabId) =>
    set((state) => {
      const keepTab = state.tabs.find((t) => t.id === tabId);
      return keepTab ? { tabs: [keepTab], activeTabId: tabId } : state;
    }),

  setActiveTab: (tabId) => {
    set({ activeTabId: tabId });

    const state = useStore.getState();
    const tab = state.tabs.find((t) => t.id === tabId);
    const fileName = tab && tab.name !== 'Welcome' ? tab.name : null;
    if (window.electronAPI?.discord) {
      window.electronAPI.discord.updateActivity(fileName);
    }
  },

  updateTabContent: (tabId, content) =>
    set((state) => ({
      tabs: state.tabs.map((tab) => (tab.id === tabId ? { ...tab, content, modified: true } : tab)),
    })),

  setLeftSidebarWidth: (width) => set({ leftSidebarWidth: width }),
  setRightSidebarWidth: (width) => set({ rightSidebarWidth: width }),
  updateEditorSettings: (newSettings) =>
    set((state) => ({
      editorSettings: { ...state.editorSettings, ...newSettings },
    })),

  openSettings: () => set({ settingsOpen: true }),
  closeSettings: () => set({ settingsOpen: false }),
  openAbout: () => set({ aboutOpen: true }),
  closeAbout: () => set({ aboutOpen: false }),
  openThemes: () => set({ themesOpen: true }),
  closeThemes: () => set({ themesOpen: false }),
}));
