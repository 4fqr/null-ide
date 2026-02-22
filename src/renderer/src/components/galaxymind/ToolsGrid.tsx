import React from 'react';
import { useStore } from '../../store/store';
import styles from './ToolsGrid.module.css';
import {
  SearchIcon,
  GlobeIcon,
  NetworkIcon,
  FileIcon,
  RefreshIcon,
  DatabaseIcon,
  ZapIcon,
  ShieldIcon,
  TerminalIcon,
  ServerIcon,
  CodeIcon,
  KeyIcon,
  LockIcon,
  UnlockIcon,
  HashIcon,
  TargetIcon,
  CopyIcon,
  InfoIcon,
} from '../common/Icons';

interface Tool {
  id: string;
  name: string;
  icon: React.ReactNode;
  category: string;
  description: string;
}

const tools: Tool[] = [
  {
    id: 'port-scanner',
    name: 'Port Scanner',
    icon: <SearchIcon />,
    category: 'Network',
    description: 'Advanced port scanning & service detection',
  },
  {
    id: 'subdomain-finder',
    name: 'Subdomain Finder',
    icon: <GlobeIcon />,
    category: 'Network',
    description: 'Discover subdomains & attack surface',
  },
  {
    id: 'dns-analyzer',
    name: 'DNS Analyzer',
    icon: <NetworkIcon />,
    category: 'Network',
    description: 'DNS enumeration & zone transfers',
  },
  {
    id: 'whois-lookup',
    name: 'WHOIS Lookup',
    icon: <FileIcon />,
    category: 'Network',
    description: 'Target reconnaissance data',
  },
  {
    id: 'reverse-dns',
    name: 'Reverse DNS',
    icon: <RefreshIcon />,
    category: 'Network',
    description: 'IP to domain resolution',
  },

  {
    id: 'sql-injection',
    name: 'SQL Injection Tester',
    icon: <DatabaseIcon />,
    category: 'Web Security',
    description: 'Automated SQLi detection & exploitation',
  },
  {
    id: 'xss-detector',
    name: 'XSS Detector',
    icon: <ZapIcon />,
    category: 'Web Security',
    description: 'Find XSS vulnerabilities',
  },
  {
    id: 'header-analyzer',
    name: 'Security Headers',
    icon: <FileIcon />,
    category: 'Web Security',
    description: 'Analyze HTTP security headers',
  },
  {
    id: 'lfi-scanner',
    name: 'LFI/RFI Scanner',
    icon: <FileIcon />,
    category: 'Web Security',
    description: 'File inclusion vulnerability scanner',
  },
  {
    id: 'csrf-tester',
    name: 'CSRF Tester',
    icon: <ShieldIcon />,
    category: 'Web Security',
    description: 'Cross-site request forgery testing',
  },
  {
    id: 'directory-fuzzer',
    name: 'Directory Fuzzer',
    icon: <FileIcon />,
    category: 'Web Security',
    description: 'Discover hidden directories',
  },
  {
    id: 'command-injection',
    name: 'Command Injection',
    icon: <TerminalIcon />,
    category: 'Web Security',
    description: 'Test OS command injection',
  },
  {
    id: 'ssrf-tester',
    name: 'SSRF Tester',
    icon: <NetworkIcon />,
    category: 'Web Security',
    description: 'Server-side request forgery testing',
  },
  {
    id: 'xxe-tester',
    name: 'XXE Tester',
    icon: <CodeIcon />,
    category: 'Web Security',
    description: 'XML external entity injection',
  },
  {
    id: 'ssti-detector',
    name: 'SSTI Detector',
    icon: <CodeIcon />,
    category: 'Web Security',
    description: 'Template injection detection',
  },
  {
    id: 'file-upload-tester',
    name: 'File Upload Tester',
    icon: <FileIcon />,
    category: 'Web Security',
    description: 'Analyze upload security',
  },
  {
    id: 'ssl-scanner',
    name: 'SSL/TLS Scanner',
    icon: <LockIcon />,
    category: 'Web Security',
    description: 'Analyze SSL/TLS configuration & HSTS',
  },
  {
    id: 'http-method-tester',
    name: 'HTTP Method Tester',
    icon: <ZapIcon />,
    category: 'Web Security',
    description: 'Test dangerous HTTP methods (PUT/DELETE/TRACE)',
  },
  {
    id: 'open-redirect-scanner',
    name: 'Open Redirect Scanner',
    icon: <TargetIcon />,
    category: 'Web Security',
    description: 'Find open redirect vulnerabilities',
  },
  {
    id: 'clickjacking-tester',
    name: 'Clickjacking Tester',
    icon: <ShieldIcon />,
    category: 'Web Security',
    description: 'Test X-Frame-Options & CSP frame-ancestors',
  },
  {
    id: 'cookie-analyzer',
    name: 'Cookie Security Analyzer',
    icon: <DatabaseIcon />,
    category: 'Web Security',
    description: 'Analyze cookie security flags (Secure/HttpOnly/SameSite)',
  },
  {
    id: 'server-fingerprinter',
    name: 'Server Fingerprinter',
    icon: <ServerIcon />,
    category: 'Web Security',
    description: 'Identify server technology & CMS',
  },
  {
    id: 'robots-txt-analyzer',
    name: 'robots.txt Analyzer',
    icon: <FileIcon />,
    category: 'Web Security',
    description: 'Discover hidden paths from robots.txt',
  },
  {
    id: 'idor-tester',
    name: 'IDOR Tester',
    icon: <ShieldIcon />,
    category: 'Web Security',
    description: 'Test Insecure Direct Object Reference vulnerabilities',
  },
  {
    id: 'host-header-injection',
    name: 'Host Header Injection',
    icon: <GlobeIcon />,
    category: 'Web Security',
    description: 'Test Host header injection & cache poisoning',
  },
  {
    id: 'graphql-scanner',
    name: 'GraphQL Scanner',
    icon: <DatabaseIcon />,
    category: 'API Security',
    description: 'GraphQL introspection & schema discovery',
  },
  {
    id: 'nosql-injection',
    name: 'NoSQL Injection Tester',
    icon: <DatabaseIcon />,
    category: 'Web Security',
    description: 'Test NoSQL injection vulnerabilities (MongoDB, etc.)',
  },
  {
    id: 'path-traversal',
    name: 'Path Traversal Scanner',
    icon: <FileIcon />,
    category: 'Web Security',
    description: 'Test path traversal vulnerabilities',
  },
  {
    id: 'ldap-injection',
    name: 'LDAP Injection Tester',
    icon: <DatabaseIcon />,
    category: 'Web Security',
    description: 'Test LDAP injection vulnerabilities',
  },
  {
    id: 'xpath-injection',
    name: 'XPath Injection Tester',
    icon: <CodeIcon />,
    category: 'Web Security',
    description: 'Test XPath injection vulnerabilities',
  },
  {
    id: 'jwt-algorithm-confusion',
    name: 'JWT Algorithm Confusion',
    icon: <KeyIcon />,
    category: 'API Security',
    description: 'Test JWT token for algorithm confusion attacks',
  },
  {
    id: 'race-condition-tester',
    name: 'Race Condition Tester',
    icon: <ZapIcon />,
    category: 'Web Security',
    description: 'Test for race conditions with concurrent requests',
  },
  {
    id: 'cache-poisoning-scanner',
    name: 'Cache Poisoning Scanner',
    icon: <ServerIcon />,
    category: 'Web Security',
    description: 'Test for web cache poisoning vulnerabilities',
  },
  {
    id: 'dom-xss-scanner',
    name: 'DOM XSS Scanner',
    icon: <CodeIcon />,
    category: 'Web Security',
    description: 'Analyze JavaScript for DOM-based XSS',
  },
  {
    id: 'dns-rebinding-tester',
    name: 'DNS Rebinding Tester',
    icon: <GlobeIcon />,
    category: 'Network',
    description: 'Test for DNS rebinding attack vulnerabilities',
  },
  {
    id: 'api-rate-limit-tester',
    name: 'API Rate Limit Tester',
    icon: <ZapIcon />,
    category: 'API Security',
    description: 'Test API endpoints for rate limiting',
  },

  {
    id: 'reverse-shell',
    name: 'Reverse Shell Generator',
    icon: <TerminalIcon />,
    category: 'Payloads',
    description: 'Generate reverse shell payloads',
  },
  {
    id: 'payload-encoder',
    name: 'Payload Encoder',
    icon: <CodeIcon />,
    category: 'Payloads',
    description: 'Encode payloads to bypass filters',
  },
  {
    id: 'webshell-generator',
    name: 'Web Shell Generator',
    icon: <TerminalIcon />,
    category: 'Payloads',
    description: 'PHP/ASP/JSP web shells',
  },
  {
    id: 'obfuscator',
    name: 'Code Obfuscator',
    icon: <CodeIcon />,
    category: 'Payloads',
    description: 'Obfuscate JavaScript/PowerShell',
  },
  {
    id: 'shellcode-generator',
    name: 'Shellcode Generator',
    icon: <TargetIcon />,
    category: 'Payloads',
    description: 'Generate shellcode for exploits',
  },

  {
    id: 'hash-cracker',
    name: 'Hash Cracker',
    icon: <HashIcon />,
    category: 'Crypto',
    description: 'Crack MD5/SHA hashes',
  },
  {
    id: 'hash-generator',
    name: 'Hash Generator',
    icon: <HashIcon />,
    category: 'Crypto',
    description: 'Generate cryptographic hashes',
  },
  {
    id: 'encryption-tool',
    name: 'Encryption Tool',
    icon: <LockIcon />,
    category: 'Crypto',
    description: 'AES/RSA encryption',
  },
  {
    id: 'jwt-cracker',
    name: 'JWT Cracker',
    icon: <KeyIcon />,
    category: 'Crypto',
    description: 'Crack weak JWT secrets',
  },
  {
    id: 'base64-tool',
    name: 'Base64/Hex Tool',
    icon: <CodeIcon />,
    category: 'Crypto',
    description: 'Multi-format encoding',
  },
  {
    id: 'certificate-analyzer',
    name: 'Certificate Analyzer',
    icon: <LockIcon />,
    category: 'Crypto',
    description: 'X.509 SSL/TLS certificate analysis',
  },

  {
    id: 'api-tester',
    name: 'API Tester',
    icon: <ServerIcon />,
    category: 'API',
    description: 'REST/GraphQL/SOAP testing',
  },
  {
    id: 'packet-analyzer',
    name: 'Packet Analyzer',
    icon: <NetworkIcon />,
    category: 'API',
    description: 'Analyze network packets',
  },
  {
    id: 'request-smuggling',
    name: 'HTTP Smuggling',
    icon: <ServerIcon />,
    category: 'API',
    description: 'Test request smuggling',
  },
  {
    id: 'cors-tester',
    name: 'CORS Tester',
    icon: <GlobeIcon />,
    category: 'API',
    description: 'Test CORS misconfigurations',
  },

  {
    id: 'password-generator',
    name: 'Password Generator',
    icon: <KeyIcon />,
    category: 'Auth',
    description: 'Generate strong passwords',
  },
  {
    id: 'jwt-decoder',
    name: 'JWT Decoder',
    icon: <KeyIcon />,
    category: 'Auth',
    description: 'Decode & analyze JWT tokens',
  },
  {
    id: 'oauth-tester',
    name: 'OAuth Tester',
    icon: <UnlockIcon />,
    category: 'Auth',
    description: 'Test OAuth flows',
  },

  {
    id: 'regex-tester',
    name: 'Regex Tester',
    icon: <SearchIcon />,
    category: 'Dev Tools',
    description: 'Test regex patterns',
  },
  {
    id: 'json-formatter',
    name: 'JSON Formatter',
    icon: <CodeIcon />,
    category: 'Dev Tools',
    description: 'Format & validate JSON',
  },
  {
    id: 'uuid-generator',
    name: 'UUID Generator',
    icon: <CopyIcon />,
    category: 'Dev Tools',
    description: 'Generate unique IDs',
  },
  {
    id: 'timestamp-converter',
    name: 'Timestamp Tool',
    icon: <InfoIcon />,
    category: 'Dev Tools',
    description: 'Unix/ISO timestamp conversion',
  },
  {
    id: 'color-converter',
    name: 'Color Converter',
    icon: <InfoIcon />,
    category: 'Dev Tools',
    description: 'HEX/RGB/HSL conversion',
  },
  {
    id: 'diff-viewer',
    name: 'Diff Viewer',
    icon: <RefreshIcon />,
    category: 'Dev Tools',
    description: 'Compare code changes',
  },
  {
    id: 'markdown-preview',
    name: 'Markdown Preview',
    icon: <FileIcon />,
    category: 'Dev Tools',
    description: 'Live markdown rendering',
  },

  {
    id: 'ssrf-advanced',
    name: 'SSRF Advanced',
    icon: <NetworkIcon />,
    category: 'Web Security',
    description: 'Multi-protocol SSRF testing with file://, gopher://, dict://',
  },
  {
    id: 'xxe-advanced',
    name: 'XXE Advanced',
    icon: <CodeIcon />,
    category: 'Web Security',
    description: 'XML External Entity injection scanner',
  },
  {
    id: 'crlf-injection',
    name: 'CRLF Injection',
    icon: <NetworkIcon />,
    category: 'Web Security',
    description: 'HTTP Response Splitting & header injection',
  },
  {
    id: 'template-injection',
    name: 'Template Injection',
    icon: <CodeIcon />,
    category: 'Web Security',
    description: 'Jinja2, Twig, Freemarker template injection testing',
  },
  {
    id: 'deserialization-scanner',
    name: 'Deserialization Scanner',
    icon: <DatabaseIcon />,
    category: 'Web Security',
    description: 'Java, Python, PHP, .NET deserialization attacks',
  },
  {
    id: 'mass-assignment',
    name: 'Mass Assignment',
    icon: <CodeIcon />,
    category: 'Web Security',
    description: 'Parameter binding vulnerability scanner',
  },
  {
    id: 'prototype-pollution',
    name: 'Prototype Pollution',
    icon: <CodeIcon />,
    category: 'Web Security',
    description: 'Node.js prototype pollution testing',
  },
  {
    id: 'websocket-security',
    name: 'WebSocket Security',
    icon: <NetworkIcon />,
    category: 'Web Security',
    description: 'WebSocket connection security testing',
  },
  {
    id: 'http2-scanner',
    name: 'HTTP/2 Scanner',
    icon: <NetworkIcon />,
    category: 'Web Security',
    description: 'HTTP/2 vulnerabilities (Rapid Reset, Request Smuggling)',
  },
  {
    id: 'blind-xss-hunter',
    name: 'Blind XSS Hunter',
    icon: <ZapIcon />,
    category: 'Web Security',
    description: 'Blind XSS payload generator & callback handler',
  },
  {
    id: 'csp-bypass',
    name: 'CSP Bypass',
    icon: <ShieldIcon />,
    category: 'Web Security',
    description: 'Content Security Policy bypass analyzer',
  },
  {
    id: 'sri-analyzer',
    name: 'SRI Analyzer',
    icon: <ShieldIcon />,
    category: 'Web Security',
    description: 'Subresource Integrity checker',
  },
  {
    id: 'hsts-checker',
    name: 'HSTS Checker',
    icon: <LockIcon />,
    category: 'Web Security',
    description: 'HSTS security validation & preload status',
  },
  {
    id: 'graphql-advanced',
    name: 'GraphQL Advanced',
    icon: <DatabaseIcon />,
    category: 'Web Security',
    description: 'Advanced GraphQL introspection & security testing',
  },

  {
    id: 'auth-bypass',
    name: 'Authentication Bypass',
    icon: <UnlockIcon />,
    category: 'Authentication',
    description: 'SQLi, NoSQL, LDAP, XPath injection bypasses',
  },
  {
    id: 'authz-bypass',
    name: 'Authorization Bypass',
    icon: <UnlockIcon />,
    category: 'Authentication',
    description: 'IDOR, Path Traversal, HTTP Verb Tampering',
  },
  {
    id: 'session-mgmt',
    name: 'Session Management',
    icon: <KeyIcon />,
    category: 'Authentication',
    description: 'Session fixation, token entropy, cookie flags',
  },
  {
    id: 'oauth2-scanner',
    name: 'OAuth 2.0 Scanner',
    icon: <KeyIcon />,
    category: 'Authentication',
    description: 'OAuth 2.0 security flaw detection',
  },
  {
    id: 'saml-scanner',
    name: 'SAML Scanner',
    icon: <LockIcon />,
    category: 'Authentication',
    description: 'SAML assertion validation & signature wrapping',
  },
  {
    id: 'jwt-weak-secret',
    name: 'JWT Weak Secret',
    icon: <HashIcon />,
    category: 'Authentication',
    description: 'JWT weak secret cracker',
  },
  {
    id: 'api-key-scanner',
    name: 'API Key Scanner',
    icon: <KeyIcon />,
    category: 'Authentication',
    description: 'Scan for exposed API keys in source code',
  },
  {
    id: 'password-policy-checker',
    name: 'Password Policy',
    icon: <LockIcon />,
    category: 'Authentication',
    description: 'Password strength & policy analyzer',
  },

  
  {
    id: 'cloud-metadata',
    name: 'Cloud Metadata',
    icon: <ServerIcon />,
    category: 'Cloud Security',
    description: 'AWS, Azure, GCP, DigitalOcean metadata endpoints',
  },
  {
    id: 's3-scanner',
    name: 'S3 Scanner',
    icon: <DatabaseIcon />,
    category: 'Cloud Security',
    description: 'S3 bucket permission testing',
  },
  {
    id: 'docker-scanner',
    name: 'Docker Scanner',
    icon: <ServerIcon />,
    category: 'Cloud Security',
    description: 'Exposed Docker API detection',
  },
  {
    id: 'k8s-scanner',
    name: 'Kubernetes Scanner',
    icon: <ServerIcon />,
    category: 'Cloud Security',
    description: 'K8s API unauthorized access testing',
  },
  {
    id: 'redis-scanner',
    name: 'Redis Scanner',
    icon: <DatabaseIcon />,
    category: 'Cloud Security',
    description: 'Redis unauthorized access & dangerous commands',
  },
  {
    id: 'mongo-scanner',
    name: 'MongoDB Scanner',
    icon: <DatabaseIcon />,
    category: 'Cloud Security',
    description: 'MongoDB authentication bypass & injection',
  },
  {
    id: 'elastic-scanner',
    name: 'Elasticsearch Scanner',
    icon: <DatabaseIcon />,
    category: 'Cloud Security',
    description: 'Elasticsearch exposure & data leakage',
  },
  {
    id: 'memcached-scanner',
    name: 'Memcached Scanner',
    icon: <DatabaseIcon />,
    category: 'Cloud Security',
    description: 'Memcached exposure & DDoS amplification',
  },
  {
    id: 'etcd-scanner',
    name: 'etcd Scanner',
    icon: <ServerIcon />,
    category: 'Cloud Security',
    description: 'etcd key-value store exposure',
  },
  {
    id: 'consul-scanner',
    name: 'Consul Scanner',
    icon: <ServerIcon />,
    category: 'Cloud Security',
    description: 'Consul API exposure & secrets',
  },

  
  {
    id: 'cert-transparency',
    name: 'Certificate Transparency',
    icon: <LockIcon />,
    category: 'Network Security',
    description: 'CT log monitoring for subdomain discovery',
  },
  {
    id: 'tls-scanner',
    name: 'TLS Scanner',
    icon: <LockIcon />,
    category: 'Network Security',
    description: 'Weak cipher detection & TLS analysis',
  },
  {
    id: 'vnc-scanner',
    name: 'VNC Scanner',
    icon: <ServerIcon />,
    category: 'Network Security',
    description: 'VNC authentication bypass testing',
  },
  {
    id: 'rdp-scanner',
    name: 'RDP Scanner',
    icon: <ServerIcon />,
    category: 'Network Security',
    description: 'RDP BlueKeep & brute force detection',
  },
  {
    id: 'ftp-scanner',
    name: 'FTP Scanner',
    icon: <ServerIcon />,
    category: 'Network Security',
    description: 'FTP anonymous access testing',
  },
  {
    id: 'smb-scanner',
    name: 'SMB Scanner',
    icon: <ServerIcon />,
    category: 'Network Security',
    description: 'SMB share enumeration & EternalBlue',
  },
  {
    id: 'snmp-scanner',
    name: 'SNMP Scanner',
    icon: <NetworkIcon />,
    category: 'Network Security',
    description: 'SNMP community string testing',
  },
  {
    id: 'ldap-scanner',
    name: 'LDAP Scanner',
    icon: <DatabaseIcon />,
    category: 'Network Security',
    description: 'LDAP/AD anonymous bind testing',
  },
  {
    id: 'bgp-scanner',
    name: 'BGP Scanner',
    icon: <NetworkIcon />,
    category: 'Network Security',
    description: 'BGP route hijacking detection',
  },
  {
    id: 'arp-scanner',
    name: 'ARP Scanner',
    icon: <NetworkIcon />,
    category: 'Network Security',
    description: 'ARP spoofing attack analysis',
  },

  
  {
    id: 'padding-oracle',
    name: 'Padding Oracle',
    icon: <HashIcon />,
    category: 'Cryptography',
    description: 'Padding oracle attack testing',
  },
  {
    id: 'hash-extension',
    name: 'Hash Extension',
    icon: <HashIcon />,
    category: 'Cryptography',
    description: 'Hash length extension attack',
  },
  {
    id: 'rsa-analyzer',
    name: 'RSA Analyzer',
    icon: <KeyIcon />,
    category: 'Cryptography',
    description: 'RSA key strength analysis',
  },
  {
    id: 'cipher-id',
    name: 'Cipher ID',
    icon: <CodeIcon />,
    category: 'Cryptography',
    description: 'Identify encryption algorithms',
  },
  {
    id: 'stego-detector',
    name: 'Steganography Detector',
    icon: <FileIcon />,
    category: 'Cryptography',
    description: 'Detect hidden data in images',
  },
  {
    id: 'random-analyzer',
    name: 'Randomness Analyzer',
    icon: <HashIcon />,
    category: 'Cryptography',
    description: 'PRNG quality testing',
  },
  {
    id: 'crypto-address',
    name: 'Crypto Address',
    icon: <KeyIcon />,
    category: 'Cryptography',
    description: 'Cryptocurrency address generator/validator',
  },

  
  {
    id: 'dns-rebind',
    name: 'DNS Rebinding',
    icon: <NetworkIcon />,
    category: 'Advanced',
    description: 'DNS rebinding attack analyzer',
  },
  {
    id: 'race-condition',
    name: 'Race Condition',
    icon: <ZapIcon />,
    category: 'Advanced',
    description: 'TOCTOU & concurrent operation testing',
  },
  {
    id: 'ssi-injection',
    name: 'SSI Injection',
    icon: <CodeIcon />,
    category: 'Advanced',
    description: 'Server-Side Include injection RCE testing',
  },
];

const ToolsGrid: React.FC = () => {
  const { setActiveGalaxyTool } = useStore();

  const categories = Array.from(new Set(tools.map((t) => t.category)));

  return (
    <div className={styles.toolsGrid}>
      <div className={styles.header}>
        <h1 className={styles.title}>
          <span className={styles.titleIcon}>
            <ZapIcon />
          </span>
          Utility Arsenal
        </h1>
        <p className={styles.subtitle}>
          Professional Penetration Testing & Security Research Tools
        </p>
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
              {tools.filter((t) => t.category === category).length}
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
