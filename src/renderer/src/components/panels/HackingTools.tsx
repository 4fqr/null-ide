import React from 'react';
import { useStore } from '../../store/store';
import styles from './ToolsPanel.module.css';

const HackingTools: React.FC = () => {
  const { setMode, setActiveGalaxyTool } = useStore();

  const launchTool = (toolId: string) => {
    setMode('galaxymind');
    setActiveGalaxyTool(toolId);
  };

  const tools = [
    { id: 'port-scanner', name: 'Port Scanner', icon: '🔍', category: 'Network' },
    { id: 'subdomain-finder', name: 'Subdomain Finder', icon: '🌐', category: 'Recon' },
    { id: 'dns-analyzer', name: 'DNS Analyzer', icon: '📡', category: 'Network' },
    { id: 'whois-lookup', name: 'WHOIS Lookup', icon: '📋', category: 'Recon' },
    { id: 'header-analyzer', name: 'Header Analyzer', icon: '📑', category: 'Security' },
    { id: 'sql-injection', name: 'SQL Injection Tester', icon: '💉', category: 'Security' },
    { id: 'xss-detector', name: 'XSS Detector', icon: '⚡', category: 'Security' },
    { id: 'uptime-checker', name: 'Uptime Checker', icon: '⏱️', category: 'Monitoring' },
  ];

  return (
    <div className={styles.panel}>
      <div className={styles.panelHeader}>
        <span className={styles.panelIcon}>🔒</span>
        <h3 className={styles.panelTitle}>Hacking Tools</h3>
      </div>
      
      <div className={styles.panelContent}>
        <p className={styles.panelDescription}>
          Quick access to security testing and penetration testing tools. 
          Click any tool below to launch it in GalaxyMind mode.
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

        <div className={styles.disclaimer}>
          <strong>⚠️ Legal Notice:</strong> These tools are for authorized security testing only. 
          Unauthorized use is illegal.
        </div>
      </div>
    </div>
  );
};

export default HackingTools;




