import React from 'react';
import { useStore } from '../../store/store';
import styles from './StatusBar.module.css';

const StatusBar: React.FC = () => {
  const { tabs, activeTabId, mode } = useStore();
  const activeTab = tabs.find((tab) => tab.id === activeTabId);

  return (
    <div className={styles.statusBar}>
      <div className={styles.left}>
        {activeTab && (
          <>
            <div className={styles.item}>
              <span className={styles.language}>{activeTab.language.toUpperCase()}</span>
            </div>
            {activeTab.modified && (
              <>
                <div className={styles.separator} />
                <div className={styles.item}>
                  <span className={styles.modified}>Modified</span>
                </div>
              </>
            )}
          </>
        )}
      </div>

      <div className={styles.center}>
        <div className={styles.item}>
          <span className={styles.mode}>{mode === 'code' ? 'Code Mode' : 'Utility Mode'}</span>
        </div>
      </div>

      <div className={styles.right}>
        <div className={styles.item}>
          <span className={styles.version}>v3.0.0</span>
        </div>
      </div>
    </div>
  );
};

export default StatusBar;
