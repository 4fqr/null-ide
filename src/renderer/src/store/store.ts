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
}

interface UIState {
  // Mode switching
  mode: 'deepzero' | 'galaxymind';
  setMode: (mode: 'deepzero' | 'galaxymind') => void;
  
  // Sidebar visibility
  leftSidebarVisible: boolean;
  rightSidebarVisible: boolean;
  terminalVisible: boolean;
  terminalHeight: number;
  leftSidebarWidth: number;
  rightSidebarWidth: number;
  
  // Active sections
  activeLeftPanel: string;
  activeGalaxyTool: string | null;
  
  // Editor tabs
  tabs: EditorTab[];
  activeTabId: string | null;
  
  // GalaxyMind state
  apiRequests: APIRequest[];
  apiHistory: Array<{ request: APIRequest; response: APIResponse }>;
  toolResults: ToolResult[];
  
  // Editor settings
  editorSettings: {
    fontSize: number;
    tabSize: number;
    wordWrap: boolean;
    minimap: boolean;
  };
  
  // Modals
  settingsOpen: boolean;
  aboutOpen: boolean;
  
  // Theme
  theme: 'dark';
  
  // Selection and content
  selectedText: string;
  setSelectedText: (text: string) => void;
  
  // Actions
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
  
  // GalaxyMind actions
  addAPIRequest: (request: APIRequest) => void;
  addToAPIHistory: (request: APIRequest, response: APIResponse) => void;
  addToolResult: (result: ToolResult) => void;
  clearToolResults: () => void;
  
  openSettings: () => void;
  closeSettings: () => void;
  openAbout: () => void;
  closeAbout: () => void;
}

export const useStore = create<UIState>((set) => ({
  // Initial state
  mode: 'deepzero',
  leftSidebarVisible: true,
  rightSidebarVisible: true,
  terminalVisible: false,
  terminalHeight: 250,
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
      content: `# Welcome to Null IDE

**NullSec - The Ultimate Hacker & Master Programmer IDE**

## Quick Start

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

## Features

✓ Monaco Editor with VS Code engine
✓ 28 GalaxyMind security & developer tools
✓ Embedded DeepHat AI assistant
✓ Privacy-focused (local-only storage)
✓ Full keyboard shortcuts support

## Mode Switching

**⚡ DeepZero Mode**: Full-featured code editor with Monaco Editor
**🌌 GalaxyMind Mode**: 28 security testing and developer utility tools

## GalaxyMind Tools (28 Total)

**🔐 Security Tools (8)**
- Port Scanner, Subdomain Finder, DNS Analyzer
- WHOIS Lookup, Header Analyzer
- SQL Injection Tester, XSS Detector, Uptime Checker

**🛠️ Developer Tools (20)**
- Base64/URL/Hash/JWT tools
- JSON Formatter/Beautifier
- Regex Tester, UUID Generator
- Timestamp Converter, Password Generator
- Color Converter, HTML Entity Encoder
- Markdown Preview, QR Code Generator
- Lorem Ipsum Generator, Diff Viewer
- CSS Minifier, Slug Generator, Cron Generator

## Left Sidebar

- **Explorer**: Browse and manage files
- **Hacking Tools**: Launch security testing tools
- **Utilities**: Launch developer utilities
- **Extensions**: Manage extensions

## Right Sidebar

Access DeepHat AI - your uncensored hacker AI assistant.

---

**Privacy Notice**: All your code and data stays local. No telemetry, no tracking.
`,
      modified: false,
    },
  ],
  activeTabId: 'welcome',
  settingsOpen: false,
  aboutOpen: false,
  theme: 'dark',
  
  // Actions
  setMode: (mode) => set({ mode }),
  setSelectedText: (text) => set({ selectedText: text }),
  toggleLeftSidebar: () => set((state) => ({ leftSidebarVisible: !state.leftSidebarVisible })),
  toggleRightSidebar: () => set((state) => ({ rightSidebarVisible: !state.rightSidebarVisible })),
  toggleTerminal: () => set((state) => ({ terminalVisible: !state.terminalVisible })),
  setTerminalHeight: (height) => set({ terminalHeight: height }),
  setActiveLeftPanel: (panel) => set({ activeLeftPanel: panel }),
  setActiveGalaxyTool: (tool) => set({ activeGalaxyTool: tool }),
  
  // GalaxyMind actions
  addAPIRequest: (request) => set((state) => ({ 
    apiRequests: [...state.apiRequests, request] 
  })),
  addToAPIHistory: (request, response) => set((state) => ({ 
    apiHistory: [...state.apiHistory, { request, response }] 
  })),
  addToolResult: (result) => set((state) => ({ 
    toolResults: [result, ...state.toolResults].slice(0, 100) // Keep last 100
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
    
  setActiveTab: (tabId) => set({ activeTabId: tabId }),
  
  updateTabContent: (tabId, content) =>
    set((state) => ({
      tabs: state.tabs.map((tab) =>
        tab.id === tabId ? { ...tab, content, modified: true } : tab
      ),
    })),
    
  setLeftSidebarWidth: (width) => set({ leftSidebarWidth: width }),
  setRightSidebarWidth: (width) => set({ rightSidebarWidth: width }),
  updateEditorSettings: (newSettings) => 
    set((state) => ({ 
      editorSettings: { ...state.editorSettings, ...newSettings } 
    })),
    
  openSettings: () => set({ settingsOpen: true }),
  closeSettings: () => set({ settingsOpen: false }),
  openAbout: () => set({ aboutOpen: true }),
  closeAbout: () => set({ aboutOpen: false }),
}));
