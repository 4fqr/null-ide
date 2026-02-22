import React, { useEffect } from 'react';
import { useStore } from './store/store';
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

  useEffect(() => {
    initializeTheme();
  }, []);

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
        });
        return;
      }

      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        const { activeTabId, tabs } = store;
        if (activeTabId) {
          const tab = tabs.find((t) => t.id === activeTabId);
          if (tab && tab.path) {
            window.electronAPI.fs.writeFile(tab.path, tab.content);
          }
        }
        return;
      }

      if (e.ctrlKey && e.key === 'w') {
        e.preventDefault();
        if (store.activeTabId) {
          store.closeTab(store.activeTabId);
        }
        return;
      }

      if (e.ctrlKey && e.shiftKey && e.key === 'W') {
        e.preventDefault();
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
      </div>
    </ErrorBoundary>
  );
};

export default App;
