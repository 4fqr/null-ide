import { create } from 'zustand';

export interface EditorTab {
  id: string;
  path: string;
  name: string;
  language: string;
  content: string;
  originalContent: string;
  modified: boolean;
}

export interface EditorSettingsState {
  fontSize: number;
  tabSize: number;
  wordWrap: boolean;
  minimap: boolean;
  lineNumbers: 'on' | 'off' | 'relative';
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

  toggleLeftSidebar: () => void;
  toggleRightSidebar: () => void;
  toggleTerminal: () => void;
  setTerminalHeight: (height: number) => void;
  setLeftSidebarWidth: (width: number) => void;
  setRightSidebarWidth: (width: number) => void;

  tabs: EditorTab[];
  activeTabId: string | null;
  openTab: (tab: EditorTab) => void;
  closeTab: (tabId: string) => void;
  closeAllTabs: () => void;
  closeOtherTabs: (tabId: string) => void;
  setActiveTab: (tabId: string) => void;
  updateTabContent: (tabId: string, content: string) => void;
  markTabSaved: (tabId: string) => void;
  revertTabContent: (tabId: string) => void;

  apiRequests: APIRequest[];
  addAPIRequest: (request: APIRequest) => void;

  toolResults: ToolResult[];
  addToolResult: (result: ToolResult) => void;
  clearToolResults: () => void;

  settingsOpen: boolean;
  aboutOpen: boolean;
  themesOpen: boolean;
  openSettings: () => void;
  closeSettings: () => void;
  openAbout: () => void;
  closeAbout: () => void;
  openThemes: () => void;
  closeThemes: () => void;

  workspacePath: string;
  setWorkspacePath: (path: string) => void;

  activeLeftPanel: string;
  setActiveLeftPanel: (panelId: string) => void;

  editorSettings: EditorSettingsState;
  updateEditorSettings: (settings: Partial<EditorSettingsState>) => void;

  activeGalaxyTool: string | null;
  setActiveGalaxyTool: (toolId: string | null) => void;
}

export const useStore = create<UIState>((set) => ({
  mode: 'code',
  setMode: (mode) => set({ mode }),

  leftSidebarVisible: true,
  rightSidebarVisible: false,
  terminalVisible: false,
  terminalHeight: 200,
  leftSidebarWidth: 260,
  rightSidebarWidth: 300,

  toggleLeftSidebar: () => set((state) => ({ leftSidebarVisible: !state.leftSidebarVisible })),
  toggleRightSidebar: () => set((state) => ({ rightSidebarVisible: !state.rightSidebarVisible })),
  toggleTerminal: () => set((state) => ({ terminalVisible: !state.terminalVisible })),
  setTerminalHeight: (height) => set({ terminalHeight: height }),
  setLeftSidebarWidth: (width) => set({ leftSidebarWidth: width }),
  setRightSidebarWidth: (width) => set({ rightSidebarWidth: width }),

  tabs: [
    {
      id: 'welcome',
      path: '',
      name: 'Welcome',
      language: 'markdown',
      content: `# Welcome to Null IDE

**Security-Focused Code Editor for Linux**

## Features

- 120+ Security Tools
- Monaco Editor with 112 language support
- Integrated Terminal
- VS Code-like File Explorer
- DeepHat AI Integration (app.deephat.ai)
- Live Preview Server (localhost:8080)

**v3.5.0 Updates**: DeepHat AI sidebar with OAuth login, Go Live button for live preview, enhanced webview support, improved status bar
`,
      originalContent: `# Welcome to Null IDE

**Security-Focused Code Editor for Linux**

## Features

- 120+ Security Tools
- Monaco Editor with 112 language support
- Integrated Terminal
- VS Code-like File Explorer
- DeepHat AI Integration (app.deephat.ai)
- Live Preview Server (localhost:8080)

**v3.5.0 Updates**: DeepHat AI sidebar with OAuth login, Go Live button for live preview, enhanced webview support, improved status bar
`,
      modified: false,
    },
  ],
  activeTabId: 'welcome',

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
    set((state) => ({
      tabs: state.tabs.filter((t) => t.id === tabId),
      activeTabId: tabId,
    })),

  setActiveTab: (tabId) => set({ activeTabId: tabId }),

  updateTabContent: (tabId, content) =>
    set((state) => ({
      tabs: state.tabs.map((tab) =>
        tab.id === tabId ? { ...tab, content, modified: content !== tab.originalContent } : tab
      ),
    })),

  markTabSaved: (tabId) =>
    set((state) => ({
      tabs: state.tabs.map((tab) =>
        tab.id === tabId ? { ...tab, modified: false, originalContent: tab.content } : tab
      ),
    })),

  revertTabContent: (tabId) =>
    set((state) => ({
      tabs: state.tabs.map((tab) =>
        tab.id === tabId ? { ...tab, content: tab.originalContent, modified: false } : tab
      ),
    })),

  apiRequests: [],
  addAPIRequest: (request) =>
    set((state) => ({
      apiRequests: [request, ...state.apiRequests].slice(0, 50),
    })),

  toolResults: [],
  addToolResult: (result) =>
    set((state) => ({
      toolResults: [result, ...state.toolResults].slice(0, 100),
    })),
  clearToolResults: () => set({ toolResults: [] }),

  settingsOpen: false,
  aboutOpen: false,
  themesOpen: false,
  openSettings: () => set({ settingsOpen: true }),
  closeSettings: () => set({ settingsOpen: false }),
  openAbout: () => set({ aboutOpen: true }),
  closeAbout: () => set({ aboutOpen: false }),
  openThemes: () => set({ themesOpen: true }),
  closeThemes: () => set({ themesOpen: false }),

  workspacePath: '',
  setWorkspacePath: (path) => set({ workspacePath: path }),

  activeLeftPanel: 'explorer',
  setActiveLeftPanel: (panelId) => set({ activeLeftPanel: panelId }),

  editorSettings: {
    fontSize: 14,
    tabSize: 2,
    wordWrap: true,
    minimap: true,
    lineNumbers: 'on',
  },
  updateEditorSettings: (settings) =>
    set((state) => ({
      editorSettings: { ...state.editorSettings, ...settings },
    })),

  activeGalaxyTool: null,
  setActiveGalaxyTool: (toolId) => set({ activeGalaxyTool: toolId }),
}));
