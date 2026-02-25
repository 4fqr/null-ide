import React, { useEffect, useState } from 'react';
import { useStore, EditorTab } from './store/store';
import { initializeTheme } from './utils/themeManager';
import TopBar from './components/layout/TopBar';
import LeftSidebar from './components/layout/LeftSidebar';
import RightSidebar from './components/layout/RightSidebar';
import StatusBar from './components/layout/StatusBar';
import TerminalPanel from './components/panels/TerminalPanelMulti';
import SettingsModal from './components/modals/SettingsModal';
import AboutModal from './components/modals/AboutModal';
import ThemeModal from './components/modals/ThemeModal';
import DeepZero from './components/modes/DeepZero';
import GalaxyMind from './components/modes/GalaxyMind';
import './styles/themes.css';
import './styles/animations.css';
import styles from './App.module.css';

class ErrorBoundary extends React.Component<
  { children: React.ReactNode },
  { hasError: boolean; error: unknown; info: React.ErrorInfo | null }
> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null, info: null };
  }

  static getDerivedStateFromError(error: unknown) {
    return { hasError: true, error };
  }

  componentDidCatch(error: unknown, info: React.ErrorInfo) {
    console.error('Uncaught error:', error, info);
    this.setState({ info });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            padding: 40,
            color: '#ff4444',
            background: '#111',
            height: '100vh',
            overflow: 'auto',
            fontFamily: 'monospace',
          }}
        >
          <h1 style={{ fontSize: 24, marginBottom: 20 }}>CRITICAL RENDER ERROR</h1>
          <div style={{ background: '#222', padding: 20, borderRadius: 8 }}>
            <h3 style={{ color: '#fff', margin: 0 }}>{this.state.error?.toString()}</h3>
            <pre style={{ color: '#888', whiteSpace: 'pre-wrap', marginTop: 20 }}>
              {this.state.info?.componentStack}
            </pre>
          </div>
          <button
            onClick={() => window.location.reload()}
            style={{
              marginTop: 20,
              padding: '10px 20px',
              background: '#00ffaa',
              border: 'none',
              borderRadius: 4,
              cursor: 'pointer',
              fontWeight: 'bold',
            }}
          >
            RELOAD APP
          </button>
        </div>
      );
    }

    return this.props.children;
  }
}

const UnsavedDialog: React.FC<{
  tabName: string;
  onSave: () => void;
  onDiscard: () => void;
  onCancel: () => void;
}> = ({ tabName, onSave, onDiscard, onCancel }) => (
  <div
    style={{
      position: 'fixed',
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      background: 'rgba(0, 0, 0, 0.7)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 10000,
    }}
  >
    <div
      style={{
        background: '#1e1e1e',
        border: '1px solid #444',
        borderRadius: 8,
        padding: 24,
        minWidth: 400,
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.5)',
      }}
    >
      <h3 style={{ margin: '0 0 16px 0', color: '#fff', fontSize: 18 }}>Unsaved Changes</h3>
      <p style={{ margin: '0 0 24px 0', color: '#aaa', fontSize: 14 }}>
        Do you want to save changes to "{tabName}"?
      </p>
      <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
        <button
          onClick={onCancel}
          style={{
            padding: '8px 16px',
            background: 'transparent',
            border: '1px solid #555',
            borderRadius: 4,
            color: '#aaa',
            cursor: 'pointer',
          }}
        >
          Cancel
        </button>
        <button
          onClick={onDiscard}
          style={{
            padding: '8px 16px',
            background: 'transparent',
            border: '1px solid #555',
            borderRadius: 4,
            color: '#f44',
            cursor: 'pointer',
          }}
        >
          Don't Save
        </button>
        <button
          onClick={onSave}
          style={{
            padding: '8px 16px',
            background: '#00d4aa',
            border: 'none',
            borderRadius: 4,
            color: '#000',
            cursor: 'pointer',
            fontWeight: 'bold',
          }}
        >
          Save
        </button>
      </div>
    </div>
  </div>
);

const App: React.FC = () => {
  console.log('App rendering...');
  const {
    mode,
    leftSidebarVisible,
    rightSidebarVisible,
    terminalVisible,
    terminalHeight,
    setTerminalHeight,
    settingsOpen,
    aboutOpen,
    closeSettings,
    closeAbout,
  } = useStore();

  const [unsavedDialog, setUnsavedDialog] = useState<{
    tabId: string;
    tabName: string;
    action: 'close' | 'closeAll';
  } | null>(null);

  useEffect(() => {
    initializeTheme();
  }, []);

  const saveTab = async (tabId: string): Promise<boolean> => {
    const store = useStore.getState();
    const tab = store.tabs.find((t) => t.id === tabId);
    if (!tab) return false;

    if (tab.path) {
      await window.electronAPI.fs.writeFile(tab.path, tab.content);
      store.markTabSaved(tabId);
      return true;
    } else {
      const result = await window.electronAPI.dialog.saveFile();
      if (!result.canceled && result.filePath) {
        await window.electronAPI.fs.writeFile(result.filePath, tab.content);
        const name = result.filePath.split('/').pop() || result.filePath;
        const updatedTabs = store.tabs.map((t) =>
          t.id === tabId
            ? { ...t, path: result.filePath, name, modified: false, originalContent: tab.content }
            : t
        ) as EditorTab[];
        useStore.setState({ tabs: updatedTabs });
        return true;
      }
      return false;
    }
  };

  const closeTabWithCheck = async (tabId: string) => {
    const store = useStore.getState();
    const tab = store.tabs.find((t) => t.id === tabId);

    if (tab?.modified) {
      setUnsavedDialog({ tabId, tabName: tab.name, action: 'close' });
    } else {
      store.closeTab(tabId);
    }
  };

  const handleUnsavedSave = async () => {
    if (!unsavedDialog) return;
    const saved = await saveTab(unsavedDialog.tabId);
    if (saved) {
      const store = useStore.getState();
      if (unsavedDialog.action === 'close') {
        store.closeTab(unsavedDialog.tabId);
      }
    }
    setUnsavedDialog(null);
  };

  const handleUnsavedDiscard = () => {
    if (!unsavedDialog) return;
    const store = useStore.getState();
    if (unsavedDialog.action === 'close') {
      store.closeTab(unsavedDialog.tabId);
    }
    setUnsavedDialog(null);
  };

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const store = useStore.getState();

      if (e.ctrlKey && e.key === 'n') {
        e.preventDefault();
        store.openTab({
          id: `untitled-${Date.now()}`,
          name: 'Untitled',
          content: '',
          language: 'plaintext',
          path: '',
          modified: false,
          originalContent: '',
        });
        return;
      }

      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        if (store.activeTabId) {
          saveTab(store.activeTabId);
        }
        return;
      }

      if (e.ctrlKey && e.shiftKey && e.key === 'S') {
        e.preventDefault();
        const modifiedTabs = store.tabs.filter((t) => t.modified);
        modifiedTabs.forEach((tab) => {
          if (tab.path) {
            saveTab(tab.id);
          }
        });
        return;
      }

      if (e.ctrlKey && e.key === 'w') {
        e.preventDefault();
        if (store.activeTabId) {
          closeTabWithCheck(store.activeTabId);
        }
        return;
      }

      if (e.ctrlKey && e.shiftKey && e.key === 'W') {
        e.preventDefault();
        const modifiedTabs = store.tabs.filter((t) => t.modified);
        if (modifiedTabs.length > 0) {
          return;
        }
        store.tabs.forEach((tab) => store.closeTab(tab.id));
        return;
      }

      if (e.ctrlKey && e.key === 'Tab' && !e.shiftKey) {
        e.preventDefault();
        if (store.tabs.length > 0) {
          const currentIndex = store.tabs.findIndex((t) => t.id === store.activeTabId);
          const nextIndex = (currentIndex + 1) % store.tabs.length;
          store.setActiveTab(store.tabs[nextIndex].id);
        }
        return;
      }

      if (e.ctrlKey && e.shiftKey && e.key === 'Tab') {
        e.preventDefault();
        if (store.tabs.length > 0) {
          const currentIndex = store.tabs.findIndex((t) => t.id === store.activeTabId);
          const prevIndex = (currentIndex - 1 + store.tabs.length) % store.tabs.length;
          store.setActiveTab(store.tabs[prevIndex].id);
        }
        return;
      }

      if (e.ctrlKey && e.key === 'b') {
        e.preventDefault();
        store.toggleLeftSidebar();
        return;
      }

      if (e.ctrlKey && e.shiftKey && e.key === 'B') {
        e.preventDefault();
        store.toggleRightSidebar();
        return;
      }

      if (e.ctrlKey && e.key === '`') {
        e.preventDefault();
        store.toggleTerminal();
        return;
      }

      if (e.ctrlKey && e.key === ',') {
        e.preventDefault();
        store.openSettings();
        return;
      }
    };

    window.addEventListener('keydown', handleKeyDown, true);
    return () => window.removeEventListener('keydown', handleKeyDown, true);
  }, []);

  return (
    <ErrorBoundary>
      <div className={`${styles.app} ${mode === 'utility' ? styles.utilityMode : styles.codeMode}`}>
        <TopBar />

        <div className={styles.mainContainer}>
          {leftSidebarVisible && <LeftSidebar />}
          <div className={styles.editorAndTerminal}>
            {mode === 'code' ? <DeepZero /> : <GalaxyMind />}
            <TerminalPanel
              isVisible={terminalVisible}
              height={terminalHeight}
              onHeightChange={setTerminalHeight}
            />
          </div>
          {rightSidebarVisible && <RightSidebar />}
        </div>

        <StatusBar />

        {settingsOpen && <SettingsModal onClose={closeSettings} />}
        {aboutOpen && <AboutModal onClose={closeAbout} />}
        <ThemeModal />

        {unsavedDialog && (
          <UnsavedDialog
            tabName={unsavedDialog.tabName}
            onSave={handleUnsavedSave}
            onDiscard={handleUnsavedDiscard}
            onCancel={() => setUnsavedDialog(null)}
          />
        )}
      </div>
    </ErrorBoundary>
  );
};

export default App;
