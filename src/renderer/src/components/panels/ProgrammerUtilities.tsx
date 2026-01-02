import React from 'react';
import { useStore } from '../../store/store';
import styles from './ToolsPanel.module.css';

const ProgrammerUtilities: React.FC = () => {
  const { setMode, setActiveGalaxyTool } = useStore();

  const launchTool = (toolId: string) => {
    setMode('galaxymind');
    setActiveGalaxyTool(toolId);
  };

  const tools = [
    { id: 'base64-tool', name: 'Base64 Encoder/Decoder', icon: '🔐', category: 'Encoding' },
    { id: 'url-tool', name: 'URL Encoder/Decoder', icon: '🔗', category: 'Encoding' },
    { id: 'hash-generator', name: 'Hash Generator', icon: '🔒', category: 'Crypto' },
    { id: 'jwt-decoder', name: 'JWT Decoder', icon: '🎫', category: 'Developer' },
    { id: 'json-formatter', name: 'JSON Formatter', icon: '📋', category: 'Developer' },
    { id: 'regex-tester', name: 'Regex Tester', icon: '🔍', category: 'Developer' },
    { id: 'uuid-generator', name: 'UUID Generator', icon: '🔑', category: 'Developer' },
    { id: 'timestamp-converter', name: 'Timestamp Converter', icon: '⏰', category: 'Developer' },
    { id: 'password-generator', name: 'Password Generator', icon: '🔐', category: 'Developer' },
    { id: 'color-converter', name: 'Color Converter', icon: '🎨', category: 'Developer' },
    { id: 'html-encoder', name: 'HTML Entity Encoder', icon: '🔤', category: 'Developer' },
    { id: 'markdown-preview', name: 'Markdown Preview', icon: '📝', category: 'Developer' },
    { id: 'lorem-ipsum', name: 'Lorem Ipsum Generator', icon: '📄', category: 'Developer' },
    { id: 'diff-viewer', name: 'Diff Viewer', icon: '🔄', category: 'Developer' },
    { id: 'css-minifier', name: 'CSS Minifier', icon: '🗜️', category: 'Developer' },
  ];

  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <span className={styles.panelIcon}>🛠️</span>
        <h3 className={styles.panelTitle}>Programmer Utilities</h3>
      </div>
      
      <div className={styles.panelContent}>
        <p className={styles.panelDescription}>
          Essential developer tools for encoding, formatting, and code analysis.
          Click any utility below to launch it in GalaxyMind mode.
        </p>

        <div className={styles.toolsList}>
          {tools.map(tool => (
            <button
              key={tool.id}
              className={styles.toolButton}
              onClick={() => launchTool(tool.id)}
              title={`Launch ${tool.name}`}
            >
              <span className={styles.toolIcon}>{tool.icon}</span>
              <div className={styles.toolInfo}>
                <div className={styles.toolName}>{tool.name}</div>
                <div className={styles.toolCategory}>{tool.category}</div>
              </div>
              <span className={styles.launchArrow}>→</span>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
};

export default ProgrammerUtilities;



