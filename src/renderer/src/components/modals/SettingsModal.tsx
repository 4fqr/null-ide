import React, { useState, useEffect } from 'react';
import { useStore } from '../../store/store';
import styles from './Modal.module.css';

interface SettingsModalProps {
  onClose: () => void;
}

const SettingsModal: React.FC<SettingsModalProps> = ({ onClose }) => {
  const editorSettings = useStore((state) => state.editorSettings);
  const updateEditorSettings = useStore((state) => state.updateEditorSettings);
  const [activeTab, setActiveTab] = useState('general');
  const [settings, setSettings] = useState({
    fontSize: editorSettings.fontSize,
    tabSize: editorSettings.tabSize,
    wordWrap: editorSettings.wordWrap,
    minimap: editorSettings.minimap,
    telemetry: false,
    autoSave: true,
  });

  useEffect(() => {
    const loadSettings = async () => {
      if (!window.electronAPI?.config) return;
      const result = await window.electronAPI.config.read();
      if (result.success && result.config) {
        setSettings((prev) => ({ ...prev, ...result.config }));
      }
    };
    loadSettings();
  }, []);

  const handleSave = async () => {
    if (window.electronAPI?.config) {
      await window.electronAPI.config.write(settings);
    }

    updateEditorSettings({
      fontSize: settings.fontSize,
      tabSize: settings.tabSize,
      wordWrap: settings.wordWrap,
      minimap: settings.minimap,
    });

    onClose();
  };

  const tabs = [
    { id: 'editor', name: 'Editor', icon: '📝' },
    { id: 'privacy', name: 'Privacy', icon: '🔒' },
  ];

  return (
    <div className={styles.modalOverlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <h2>⚙️ Settings</h2>
          <button className={styles.closeBtn} onClick={onClose}>
            ×
          </button>
        </div>

        <div className={styles.modalBody}>
          <div className={styles.tabs}>
            {tabs.map((tab) => (
              <button
                key={tab.id}
                className={`${styles.tab} ${activeTab === tab.id ? styles.activeTab : ''}`}
                onClick={() => setActiveTab(tab.id)}
              >
                <span className={styles.tabIcon}>{tab.icon}</span>
                <span>{tab.name}</span>
              </button>
            ))}
          </div>

          <div className={styles.tabContent}>
            {activeTab === 'privacy' && (
              <div className={styles.section}>
                <h3>🔒 Privacy & Security</h3>
                <div className={styles.privacyNotice}>
                  <p>
                    <strong>Null IDE respects your privacy.</strong>
                  </p>
                  <ul>
                    <li>✓ All code and data stored locally only</li>
                    <li>✓ No user tracking or analytics</li>
                    <li>✓ No external connections without permission</li>
                    <li>✓ Open source and transparent</li>
                  </ul>
                </div>
              </div>
            )}

            {activeTab === 'editor' && (
              <div className={styles.section}>
                <h3>📝 Editor Preferences</h3>

                <div className={styles.setting}>
                  <label>Font Size</label>
                  <input
                    type="number"
                    min="10"
                    max="24"
                    value={settings.fontSize}
                    onChange={(e) =>
                      setSettings({ ...settings, fontSize: parseInt(e.target.value) })
                    }
                  />
                  <small className="text-secondary">Editor font size (10-24px)</small>
                </div>

                <div className={styles.setting}>
                  <label>Tab Size</label>
                  <input
                    type="number"
                    min="2"
                    max="8"
                    value={settings.tabSize}
                    onChange={(e) =>
                      setSettings({ ...settings, tabSize: parseInt(e.target.value) })
                    }
                  />
                  <small className="text-secondary">Spaces per tab (2-8)</small>
                </div>

                <div className={styles.setting}>
                  <label className={styles.checkbox}>
                    <input
                      type="checkbox"
                      checked={settings.wordWrap}
                      onChange={(e) => setSettings({ ...settings, wordWrap: e.target.checked })}
                    />
                    <span>Word Wrap</span>
                  </label>
                  <small className="text-secondary">Wrap long lines</small>
                </div>

                <div className={styles.setting}>
                  <label className={styles.checkbox}>
                    <input
                      type="checkbox"
                      checked={settings.minimap}
                      onChange={(e) => setSettings({ ...settings, minimap: e.target.checked })}
                    />
                    <span>Show Minimap</span>
                  </label>
                  <small className="text-secondary">Display code minimap</small>
                </div>
              </div>
            )}
          </div>
        </div>

        <div className={styles.modalFooter}>
          <button className={styles.btnSecondary} onClick={onClose}>
            Cancel
          </button>
          <button className={styles.btnPrimary} onClick={handleSave}>
            Save Settings
          </button>
        </div>
      </div>
    </div>
  );
};

export default SettingsModal;
