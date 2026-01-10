import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

const SubdomainFinder: React.FC = () => {
  const { setActiveGalaxyTool, addToolResult } = useStore();
  const [domain, setDomain] = useState('');
  const [results, setResults] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const commonSubdomains = [
    'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
    'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'dev', 'test',
    'staging', 'api', 'admin', 'blog', 'shop', 'forum', 'support', 'wiki', 'cdn', 'portal',
  ];

  const findSubdomains = async () => {
    if (!domain.trim()) {
      setError('Domain is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: string[] = [];

      for (const sub of commonSubdomains) {
        const fullDomain = `${sub}.${domain}`;
        
        try {
          const result: any = await window.electronAPI.net.dnsLookup(fullDomain);
          
          if (result.success && result.addresses && result.addresses.length > 0) {
            found.push(`${fullDomain} (${result.addresses[0]})`);
          }
        } catch (err) {
          // Subdomain likely doesn't exist
        }

        await new Promise((resolve) => setTimeout(resolve, 100));
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Subdomain Finder',
        timestamp: Date.now(),
        input: { domain },
        output: found,
        success: true,
      });
    } catch (err: any) {
      setError(err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <h2 className={styles.toolTitle}>
          <span className={styles.toolIcon}>🌐</span>
          Subdomain Finder
        </h2>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Target Domain</label>
            <input
              type="text"
              className={styles.input}
              placeholder="example.com"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
            />
          </div>

          <button className={styles.sendButton} onClick={findSubdomains} disabled={loading}>
            {loading ? 'Scanning...' : 'Find Subdomains'}
          </button>
        </div>

        {error && (
          <div className={styles.error}>
            <strong>Error:</strong> {error}
          </div>
        )}

        {loading && (
          <div className={styles.loading}>
            <div className={styles.spinner}></div>
            <span>Scanning for subdomains...</span>
          </div>
        )}

        {results.length > 0 && (
          <div className={styles.results}>
            <h3 className={styles.sectionTitle}>Found Subdomains ({results.length})</h3>
            {results.map((subdomain) => (
              <div key={subdomain} className={styles.resultItem}>
                <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>{subdomain}</span>
              </div>
            ))}
          </div>
        )}

        {!loading && results.length === 0 && domain && (
          <div className={styles.success}>
            No subdomains found for {domain}
          </div>
        )}
      </div>
    </div>
  );
};

export default SubdomainFinder;
