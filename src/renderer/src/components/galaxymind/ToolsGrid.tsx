import React from 'react';
import { useStore } from '../../store/store';
import styles from './ToolsGrid.module.css';

interface Tool {
  id: string;
  name: string;
  icon: string;
  category: string;
  description: string;
}

const tools: Tool[] = [
  // Network Tools
  { id: 'api-tester', name: 'API Tester', icon: '🔌', category: 'Network', description: 'Test REST & GraphQL APIs' },
  { id: 'port-scanner', name: 'Port Scanner', icon: '🔍', category: 'Network', description: 'Scan ports on target hosts' },
  { id: 'dns-analyzer', name: 'DNS Analyzer', icon: '📡', category: 'Network', description: 'Analyze DNS records' },
  
  // Reconnaissance
  { id: 'subdomain-finder', name: 'Subdomain Finder', icon: '🌐', category: 'Reconnaissance', description: 'Discover subdomains' },
  { id: 'whois-lookup', name: 'WHOIS Lookup', icon: '📋', category: 'Reconnaissance', description: 'Domain registration info' },
  
  // Monitoring
  { id: 'uptime-checker', name: 'Uptime Checker', icon: '⏱️', category: 'Monitoring', description: 'Monitor website availability' },
  
  // Security Testing
  { id: 'header-analyzer', name: 'Header Analyzer', icon: '📑', category: 'Security', description: 'Analyze HTTP headers' },
  { id: 'sql-injection', name: 'SQL Injection', icon: '💉', category: 'Security', description: 'Test SQL injection vectors' },
  { id: 'xss-detector', name: 'XSS Detector', icon: '⚡', category: 'Security', description: 'Detect XSS vulnerabilities' },
  
  // Encoding & Crypto
  { id: 'base64-tool', name: 'Base64 Tool', icon: '🔐', category: 'Encoding', description: 'Encode/decode Base64' },
  { id: 'url-tool', name: 'URL Tool', icon: '🔗', category: 'Encoding', description: 'Encode/decode URLs' },
  { id: 'hash-generator', name: 'Hash Generator', icon: '🔒', category: 'Crypto', description: 'Generate SHA-256/512 hashes' },
  
  // Developer Tools
  { id: 'jwt-decoder', name: 'JWT Decoder', icon: '🎫', category: 'Developer', description: 'Decode JWT tokens' },
  { id: 'json-formatter', name: 'JSON Formatter', icon: '📋', category: 'Developer', description: 'Format & validate JSON' },
  { id: 'regex-tester', name: 'Regex Tester', icon: '🔍', category: 'Developer', description: 'Test regular expressions' },
  { id: 'uuid-generator', name: 'UUID Generator', icon: '🔑', category: 'Developer', description: 'Generate UUIDs' },
  { id: 'timestamp-converter', name: 'Timestamp Converter', icon: '⏰', category: 'Developer', description: 'Convert timestamps' },
  { id: 'password-generator', name: 'Password Generator', icon: '🔐', category: 'Developer', description: 'Generate secure passwords' },
  { id: 'color-converter', name: 'Color Converter', icon: '🎨', category: 'Developer', description: 'Convert HEX/RGB/HSL colors' },
  { id: 'html-encoder', name: 'HTML Entity Encoder', icon: '🔤', category: 'Developer', description: 'Encode/decode HTML entities' },
  { id: 'markdown-preview', name: 'Markdown Preview', icon: '📝', category: 'Developer', description: 'Live markdown preview' },
  { id: 'lorem-ipsum', name: 'Lorem Ipsum', icon: '📄', category: 'Developer', description: 'Generate placeholder text' },
  { id: 'diff-viewer', name: 'Diff Viewer', icon: '🔄', category: 'Developer', description: 'Compare text differences' },
  { id: 'css-minifier', name: 'CSS Minifier', icon: '🗜️', category: 'Developer', description: 'Minify & beautify CSS' },
  { id: 'json-beautifier', name: 'JSON Beautifier', icon: '✨', category: 'Developer', description: 'Format & minify JSON' },
  { id: 'slug-generator', name: 'Slug Generator', icon: '🔗', category: 'Developer', description: 'Generate URL slugs' },
  { id: 'cron-generator', name: 'Cron Generator', icon: '⏰', category: 'Developer', description: 'Create cron expressions' },
];

const ToolsGrid: React.FC = () => {
  const { setActiveGalaxyTool } = useStore();

  const categories = Array.from(new Set(tools.map(t => t.category)));

  return (
    <div className={styles.toolsGrid}>
      <div className={styles.header}>
        <h1 className={styles.title}>
          <span className={styles.titleIcon}>🌌</span>
          GalaxyMind
        </h1>
        <p className={styles.subtitle}>Professional Security & Penetration Testing Suite</p>
      </div>

      {categories.map((category) => (
        <div key={category} className={styles.category}>
          <h2 className={styles.categoryTitle}>{category}</h2>
          <div className={styles.toolCards}>
            {tools
              .filter((tool) => tool.category === category)
              .map((tool) => (
                <div
                  key={tool.id}
                  className={styles.toolCard}
                  onClick={() => setActiveGalaxyTool(tool.id)}
                >
                  <div className={styles.toolIcon}>{tool.icon}</div>
                  <h3 className={styles.toolName}>{tool.name}</h3>
                  <p className={styles.toolDescription}>{tool.description}</p>
                </div>
              ))}
          </div>
        </div>
      ))}
    </div>
  );
};

export default ToolsGrid;
