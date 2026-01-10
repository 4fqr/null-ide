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
  // Network & Recon
  { id: 'port-scanner', name: 'Port Scanner', icon: '🔍', category: 'Network', description: 'Advanced port scanning & service detection' },
  { id: 'subdomain-finder', name: 'Subdomain Finder', icon: '🌐', category: 'Network', description: 'Discover subdomains & attack surface' },
  { id: 'dns-analyzer', name: 'DNS Analyzer', icon: '📡', category: 'Network', description: 'DNS enumeration & zone transfers' },
  { id: 'whois-lookup', name: 'WHOIS Lookup', icon: '📋', category: 'Network', description: 'Target reconnaissance data' },
  { id: 'reverse-dns', name: 'Reverse DNS', icon: '🔄', category: 'Network', description: 'IP to domain resolution' },
  
  // Web Security
  { id: 'sql-injection', name: 'SQL Injection Tester', icon: '💉', category: 'Web Security', description: 'Automated SQLi detection & exploitation' },
  { id: 'xss-detector', name: 'XSS Detector', icon: '⚡', category: 'Web Security', description: 'Find XSS vulnerabilities' },
  { id: 'header-analyzer', name: 'Security Headers', icon: '📑', category: 'Web Security', description: 'Analyze HTTP security headers' },
  { id: 'lfi-scanner', name: 'LFI/RFI Scanner', icon: '📂', category: 'Web Security', description: 'File inclusion vulnerability scanner' },
  { id: 'csrf-tester', name: 'CSRF Tester', icon: '🛡️', category: 'Web Security', description: 'Cross-site request forgery testing' },
  { id: 'directory-fuzzer', name: 'Directory Fuzzer', icon: '📁', category: 'Web Security', description: 'Discover hidden directories' },
  { id: 'command-injection', name: 'Command Injection', icon: '💉', category: 'Web Security', description: 'Test OS command injection' },
  { id: 'ssrf-tester', name: 'SSRF Tester', icon: '🌐', category: 'Web Security', description: 'Server-side request forgery testing' },
  { id: 'xxe-tester', name: 'XXE Tester', icon: '📄', category: 'Web Security', description: 'XML external entity injection' },
  { id: 'ssti-detector', name: 'SSTI Detector', icon: '🎭', category: 'Web Security', description: 'Template injection detection' },
  { id: 'file-upload-tester', name: 'File Upload Tester', icon: '📁', category: 'Web Security', description: 'Analyze upload security' },
  
  // Payload & Exploit Tools
  { id: 'reverse-shell', name: 'Reverse Shell Generator', icon: '🐚', category: 'Payloads', description: 'Generate reverse shell payloads' },
  { id: 'payload-encoder', name: 'Payload Encoder', icon: '🔀', category: 'Payloads', description: 'Encode payloads to bypass filters' },
  { id: 'webshell-generator', name: 'Web Shell Generator', icon: '💀', category: 'Payloads', description: 'PHP/ASP/JSP web shells' },
  { id: 'obfuscator', name: 'Code Obfuscator', icon: '🌀', category: 'Payloads', description: 'Obfuscate JavaScript/PowerShell' },
  { id: 'shellcode-generator', name: 'Shellcode Generator', icon: '⚙️', category: 'Payloads', description: 'Generate shellcode for exploits' },
  
  // Crypto & Hashing
  { id: 'hash-cracker', name: 'Hash Cracker', icon: '🔨', category: 'Crypto', description: 'Crack MD5/SHA hashes' },
  { id: 'hash-generator', name: 'Hash Generator', icon: '🔒', category: 'Crypto', description: 'Generate cryptographic hashes' },
  { id: 'encryption-tool', name: 'Encryption Tool', icon: '🔐', category: 'Crypto', description: 'AES/RSA encryption' },
  { id: 'jwt-cracker', name: 'JWT Cracker', icon: '🎫', category: 'Crypto', description: 'Crack weak JWT secrets' },
  { id: 'base64-tool', name: 'Base64/Hex Tool', icon: '📝', category: 'Crypto', description: 'Multi-format encoding' },
  { id: 'certificate-analyzer', name: 'Certificate Analyzer', icon: '🔐', category: 'Crypto', description: 'X.509 SSL/TLS certificate analysis' },
  
  // API & Network Tools
  { id: 'api-tester', name: 'API Tester', icon: '🔌', category: 'API', description: 'REST/GraphQL/SOAP testing' },
  { id: 'packet-analyzer', name: 'Packet Analyzer', icon: '📦', category: 'API', description: 'Analyze network packets' },
  { id: 'request-smuggling', name: 'HTTP Smuggling', icon: '🚢', category: 'API', description: 'Test request smuggling' },
  { id: 'cors-tester', name: 'CORS Tester', icon: '🌍', category: 'API', description: 'Test CORS misconfigurations' },
  
  // Password & Auth
  { id: 'password-generator', name: 'Password Generator', icon: '🔑', category: 'Auth', description: 'Generate strong passwords' },
  { id: 'jwt-decoder', name: 'JWT Decoder', icon: '🎟️', category: 'Auth', description: 'Decode & analyze JWT tokens' },
  { id: 'oauth-tester', name: 'OAuth Tester', icon: '🔓', category: 'Auth', description: 'Test OAuth flows' },
  
  // Developer Utilities
  { id: 'regex-tester', name: 'Regex Tester', icon: '🔍', category: 'Dev Tools', description: 'Test regex patterns' },
  { id: 'json-formatter', name: 'JSON Formatter', icon: '📋', category: 'Dev Tools', description: 'Format & validate JSON' },
  { id: 'uuid-generator', name: 'UUID Generator', icon: '🆔', category: 'Dev Tools', description: 'Generate unique IDs' },
  { id: 'timestamp-converter', name: 'Timestamp Tool', icon: '⏰', category: 'Dev Tools', description: 'Unix/ISO timestamp conversion' },
  { id: 'color-converter', name: 'Color Converter', icon: '🎨', category: 'Dev Tools', description: 'HEX/RGB/HSL conversion' },
  { id: 'diff-viewer', name: 'Diff Viewer', icon: '🔄', category: 'Dev Tools', description: 'Compare code changes' },
  { id: 'markdown-preview', name: 'Markdown Preview', icon: '📝', category: 'Dev Tools', description: 'Live markdown rendering' },
];

const ToolsGrid: React.FC = () => {
  const { setActiveGalaxyTool } = useStore();

  const categories = Array.from(new Set(tools.map(t => t.category)));

  return (
    <div className={styles.toolsGrid}>
      <div className={styles.header}>
        <h1 className={styles.title}>
          <span className={styles.titleIcon}>⚡</span>
          Utility Arsenal
        </h1>
        <p className={styles.subtitle}>Professional Penetration Testing & Security Research Tools</p>
        <div className={styles.stats}>
          <span className={styles.stat}>{tools.length} Tools</span>
          <span className={styles.separator}>•</span>
          <span className={styles.stat}>{categories.length} Categories</span>
        </div>
      </div>

      {categories.map((category) => (
        <div key={category} className={styles.category}>
          <h2 className={styles.categoryTitle}>
            <span className={styles.categoryDot}></span>
            {category}
            <span className={styles.categoryCount}>
              {tools.filter(t => t.category === category).length}
            </span>
          </h2>
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
                  <div className={styles.toolHover}>
                    <span>Launch Tool →</span>
                  </div>
                </div>
              ))}
          </div>
        </div>
      ))}
    </div>
  );
};

export default ToolsGrid;
