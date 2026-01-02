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
      // Ctrl+N: New file
      if (e.ctrlKey && e.key === 'n') {
        e.preventDefault();
        useStore.getState().openTab({
          id: `untitled-${Date.now()}`,
          name: 'Untitled',
          content: '',
          language: 'plaintext',
          path: '',
          modified: false
        });
      }

      // Ctrl+S: Save file
      if (e.ctrlKey && e.key === 's') {
        e.preventDefault();
        const { activeTabId, tabs } = useStore.getState();
        if (activeTabId) {
          const tab = tabs.find(t => t.id === activeTabId);
          if (tab && tab.path) {
            window.electronAPI.fs.writeFile(tab.path, tab.content);
          }
        }
      }

      // Ctrl+W: Close tab
      if (e.ctrlKey && e.key === 'w') {
        e.preventDefault();
        const { activeTabId } = useStore.getState();
        if (activeTabId) {
          useStore.getState().closeTab(activeTabId);
        }
      }

      // Ctrl+Shift+W: Close all tabs
      if (e.ctrlKey && e.shiftKey && e.key === 'W') {
        e.preventDefault();
        const { tabs } = useStore.getState();
        tabs.forEach(tab => useStore.getState().closeTab(tab.id));
      }

      // Ctrl+Tab: Next tab
      if (e.ctrlKey && e.key === 'Tab' && !e.shiftKey) {
        e.preventDefault();
        const { tabs, activeTabId } = useStore.getState();
        if (tabs.length > 0) {
          const currentIndex = tabs.findIndex(t => t.id === activeTabId);
          const nextIndex = (currentIndex + 1) % tabs.length;
          useStore.getState().setActiveTab(tabs[nextIndex].id);
        }
      }

      // Ctrl+Shift+Tab: Previous tab
      if (e.ctrlKey && e.shiftKey && e.key === 'Tab') {
        e.preventDefault();
        const { tabs, activeTabId } = useStore.getState();
        if (tabs.length > 0) {
          const currentIndex = tabs.findIndex(t => t.id === activeTabId);
          const prevIndex = (currentIndex - 1 + tabs.length) % tabs.length;
          useStore.getState().setActiveTab(tabs[prevIndex].id);
        }
      }

      // Ctrl+B: Toggle left sidebar
      if (e.ctrlKey && e.key === 'b') {
        e.preventDefault();
        useStore.getState().toggleLeftSidebar();
      }
      
      // Ctrl+Shift+B: Toggle right sidebar
      if (e.ctrlKey && e.shiftKey && e.key === 'B') {
        e.preventDefault();
        useStore.getState().toggleRightSidebar();
      }

      // Ctrl+`: Toggle terminal
      if (e.ctrlKey && e.key === '`') {
        e.preventDefault();
        useStore.getState().toggleTerminal();
      }
      
      // Ctrl+,: Open settings
      if (e.ctrlKey && e.key === ',') {
        e.preventDefault();
        useStore.getState().openSettings();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, []);

  return (
    <div className={`${styles.app} ${mode === 'galaxymind' ? styles.galaxyMode : styles.deepzeroMode}`}>
      <TopBar />
      
      <div className={styles.mainContainer}>
        {leftSidebarVisible && <LeftSidebar />}
        <div className={styles.editorAndTerminal}>
          {mode === 'deepzero' ? <DeepZero /> : <GalaxyMind />}
          {mode === 'deepzero' && (
            <TerminalPanel 
              isVisible={terminalVisible} 
              height={terminalHeight}
              onHeightChange={setTerminalHeight}
            />
          )}
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
