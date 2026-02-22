import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { SubdomainIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function SubdomainFinder() {
  const [domain, setDomain] = useState('');
  const [results, setResults] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  const commonSubdomains = [
    'www',
    'mail',
    'ftp',
    'webmail',
    'smtp',
    'pop',
    'ns1',
    'ns2',
    'cpanel',
    'admin',
    'api',
    'blog',
    'shop',
    'forum',
    'support',
    'wiki',
    'cdn',
    'portal',
    'dev',
    'test',
    'staging',
    'm',
    'mobile',
  ];

  const findSubdomains = async () => {
    if (!domain.trim()) {
      setError('Please enter a domain');
      return;
    }

    setLoading(true);
    setError('');
    setResults([]);
    setProgress(0);

    const found: string[] = [];

    for (let i = 0; i < commonSubdomains.length; i++) {
      const sub = commonSubdomains[i];
      const fullDomain = `${sub}.${domain}`;
      setProgress(Math.round(((i + 1) / commonSubdomains.length) * 100));

      try {
        const result = await window.electronAPI.net.dnsLookup(fullDomain);
        if (result.success && result.addresses && result.addresses.length > 0) {
          found.push(`${fullDomain} (${result.addresses[0]})`);
          setResults([...found]);
        }
      } catch {}

      await new Promise((r) => setTimeout(r, 50));
    }

    setLoading(false);
    if (found.length === 0) {
      setError('No subdomains found');
    }
  };

  return (
    <ToolWrapper
      title="Subdomain Finder"
      icon={<SubdomainIcon />}
      description="Discover subdomains using DNS enumeration"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target Domain</label>
          <input
            type="text"
            className={styles.input}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={findSubdomains} disabled={loading}>
            {loading ? `Scanning... ${progress}%` : 'Find Subdomains'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setDomain('');
              setResults([]);
              setError('');
              setProgress(0);
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {loading && (
        <div className={styles.resultBox}>
          <div className={styles.progressBar}>
            <div className={styles.progressFill} style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Found Subdomains ({results.length})</span>
            <button
              className={styles.copyBtn}
              onClick={() => navigator.clipboard.writeText(results.join('\n'))}
            >
              Copy
            </button>
          </div>
          {results.map((sub, i) => (
            <div key={i} className={styles.resultItem}>
              <span className={styles.code}>{sub}</span>
            </div>
          ))}
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>Subdomain Discovery</h3>
        <ul>
          <li>Tests common subdomain prefixes via DNS</li>
          <li>Results show resolved IP addresses</li>
          <li>For comprehensive scans, use tools like Subfinder or Amass</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
