import React from 'react';
import { useStore } from '../../store/store';
import MenuBar from './MenuBar';
import { SettingsIcon, InfoIcon } from '../icons/Icons';
import styles from './TopBar.module.css';

const TopBar: React.FC = () => {
  const { tabs, activeTabId, setActiveTab, closeTab, closeAllTabs, closeOtherTabs, openSettings, openAbout, mode, setMode } = useStore();

  const handleContextMenu = (e: React.MouseEvent, tabId: string) => {
    e.preventDefault();
    // Create context menu
    const menu = document.createElement('div');
    menu.style.position = 'fixed';
    menu.style.left = `${e.clientX}px`;
    menu.style.top = `${e.clientY}px`;
    menu.style.background = 'var(--color-bg-elevated)';
    menu.style.border = '1px solid var(--color-border)';
    menu.style.borderRadius = '4px';
    menu.style.padding = '4px 0';
    menu.style.zIndex = '10000';
    menu.style.minWidth = '180px';
    menu.style.boxShadow = '0 4px 12px rgba(0,0,0,0.5)';

    const createMenuItem = (label: string, action: () => void) => {
      const item = document.createElement('div');
      item.textContent = label;
      item.style.padding = '6px 16px';
      item.style.cursor = 'pointer';
      item.style.fontSize = '13px';
      item.style.color = 'var(--color-text-primary)';
      item.onmouseenter = () => {
        item.style.background = 'var(--color-bg-hover)';
      };
      item.onmouseleave = () => {
        item.style.background = 'transparent';
      };
      item.onclick = () => {
        action();
        document.body.removeChild(menu);
      };
      return item;
    };

    menu.appendChild(createMenuItem('Close', () => closeTab(tabId)));
    menu.appendChild(createMenuItem('Close Others', () => closeOtherTabs(tabId)));
    menu.appendChild(createMenuItem('Close All', () => closeAllTabs()));

    document.body.appendChild(menu);

    const removeMenu = () => {
      if (document.body.contains(menu)) {
        document.body.removeChild(menu);
      }
      document.removeEventListener('click', removeMenu);
    };

    setTimeout(() => document.addEventListener('click', removeMenu), 100);
  };

  return (
    <div className={styles.topBarContainer}>
      <div className={styles.topBar}>
        <div className={styles.left}>
          <div className={styles.branding}>
            <span className={styles.title}>Null IDE</span>
            <span className={styles.subtitle}>NullSec</span>
          </div>
          
          {/* Mode Toggle - Moved to left side */}
          <div className={styles.modeToggle}>
            <button
              className={`${styles.modeButton} ${mode === 'deepzero' ? styles.active : ''}`}
              onClick={() => setMode('deepzero')}
            >
              <span className={styles.modeIcon}>⚡</span>
              DeepZero
            </button>
            <button
              className={`${styles.modeButton} ${mode === 'galaxymind' ? styles.active : ''}`}
              onClick={() => setMode('galaxymind')}
            >
              <span className={styles.modeIcon}>🌌</span>
              GalaxyMind
            </button>
          </div>
        </div>

        <div className={styles.center}>
          <div className={styles.tabs}>
            {tabs.map((tab) => (
              <div
                key={tab.id}
                className={`${styles.tab} ${tab.id === activeTabId ? styles.active : ''}`}
                onClick={() => setActiveTab(tab.id)}
                onContextMenu={(e) => handleContextMenu(e, tab.id)}
              >
                <span className={styles.tabName}>{tab.name}</span>
                {tab.modified && <span className={styles.modified}>●</span>}
                <button
                  className={styles.closeBtn}
                  onClick={(e) => {
                    e.stopPropagation();
                    closeTab(tab.id);
                  }}
                  title="Close"
                >
                  ×
                </button>
              </div>
            ))}
          </div>
        </div>

        <div className={styles.right}>
          <button className={styles.iconBtn} onClick={openSettings} title="Settings (Ctrl+,)">
            <SettingsIcon size={18} />
          </button>
          <button className={styles.iconBtn} onClick={openAbout} title="About">
            <InfoIcon size={18} />
          </button>
        </div>
      </div>
      <MenuBar />
    </div>
  );
};

export default TopBar;
