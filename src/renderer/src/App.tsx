import React, { useEffect } from 'react';
import { useStore } from './store/store';
import TopBar from './components/layout/TopBar';
import LeftSidebar from './components/layout/LeftSidebar';
import RightSidebar from './components/layout/RightSidebar';
import StatusBar from './components/layout/StatusBar';
import TerminalPanel from './components/panels/TerminalPanelMulti';
import SettingsModal from './components/modals/SettingsModal';
import AboutModal from './components/modals/AboutModal';
import DeepZero from './components/modes/DeepZero';
import GalaxyMind from './components/modes/GalaxyMind';
import './styles/animations.css';
import styles from './App.module.css';

const App: React.FC = () => {
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

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      const store = useStore.getState();
      
      // Ctrl+N: New file
      if (e.ctrlKey && e.key === 'n') {
        e.preventDefault();
        store.openTab({
          id: `untitled-${Date.now()}`,
          name: 'Untitled',
          content: '',
          language: 'plaintext',
          path: '',
          modified: false
        });
        return;
      }

      // Ctrl+S: Save file
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        const { activeTabId, tabs } = store;
        if (activeTabId) {
          const tab = tabs.find(t => t.id === activeTabId);
          if (tab && tab.path) {
            window.electronAPI.fs.writeFile(tab.path, tab.content);
          }
        }
        return;
      }

      // Ctrl+W: Close tab
      if (e.ctrlKey && e.key === 'w') {
        e.preventDefault();
        if (store.activeTabId) {
          store.closeTab(store.activeTabId);
        }
        return;
      }

      // Ctrl+Shift+W: Close all tabs
      if (e.ctrlKey && e.shiftKey && e.key === 'W') {
        e.preventDefault();
        store.tabs.forEach(tab => store.closeTab(tab.id));
        return;
      }

      // Ctrl+Tab: Next tab
      if (e.ctrlKey && e.key === 'Tab' && !e.shiftKey) {
        e.preventDefault();
        if (store.tabs.length > 0) {
          const currentIndex = store.tabs.findIndex(t => t.id === store.activeTabId);
          const nextIndex = (currentIndex + 1) % store.tabs.length;
          store.setActiveTab(store.tabs[nextIndex].id);
        }
        return;
      }

      // Ctrl+Shift+Tab: Previous tab
      if (e.ctrlKey && e.shiftKey && e.key === 'Tab') {
        e.preventDefault();
        if (store.tabs.length > 0) {
          const currentIndex = store.tabs.findIndex(t => t.id === store.activeTabId);
          const prevIndex = (currentIndex - 1 + store.tabs.length) % store.tabs.length;
          store.setActiveTab(store.tabs[prevIndex].id);
        }
        return;
      }

      // Ctrl+B: Toggle left sidebar
      if (e.ctrlKey && e.key === 'b') {
        e.preventDefault();
        store.toggleLeftSidebar();
        return;
      }
      
      // Ctrl+Shift+B: Toggle right sidebar
      if (e.ctrlKey && e.shiftKey && e.key === 'B') {
        e.preventDefault();
        store.toggleRightSidebar();
        return;
      }

      // Ctrl+`: Toggle terminal
      if (e.ctrlKey && e.key === '`') {
        e.preventDefault();
        store.toggleTerminal();
        return;
      }
      
      // Ctrl+,: Open settings
      if (e.ctrlKey && e.key === ',') {
        e.preventDefault();
        store.openSettings();
        return;
      }
    };

    // Use capture phase to intercept before Monaco editor
    window.addEventListener('keydown', handleKeyDown, true);
    return () => window.removeEventListener('keydown', handleKeyDown, true);
  }, []);

  return (
    <div className={`${styles.app} ${mode === 'galaxymind' ? styles.galaxyMode : styles.deepzeroMode}`}>
      <TopBar />
      
      <div className={styles.mainContainer}>
        {leftSidebarVisible && <LeftSidebar />}
        <div className={styles.editorAndTerminal}>
          {mode === 'deepzero' ? <DeepZero /> : <GalaxyMind />}
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
    </div>
  );
};

export default App;
