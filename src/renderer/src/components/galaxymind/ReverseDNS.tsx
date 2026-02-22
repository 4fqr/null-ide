import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { NetworkIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function ReverseDNS() {
  const [ip, setIp] = useState('');
  const [results, setResults] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleReverseLookup = async () => {
    if (!ip.trim()) {
      setError('Please enter an IP address');
      return;
    }

    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) {
      setError('Please enter a valid IPv4 address');
      return;
    }

    setLoading(true);
    setError('');
    setResults([]);

    try {
      const result = await window.electronAPI.net.reverseDns(ip);
      if (result.success && result.hostnames) {
        setResults(result.hostnames);
      } else {
        setError('No hostname found for this IP');
      }
    } catch (err) {
      setError('Reverse DNS lookup failed: ' + (err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Reverse DNS"
      icon={<NetworkIcon />}
      description="Perform reverse DNS lookup to find hostnames from IP addresses"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>IP Address</label>
          <input
            type="text"
            className={styles.input}
            value={ip}
            onChange={(e) => setIp(e.target.value)}
            placeholder="e.g., 8.8.8.8"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={handleReverseLookup} disabled={loading}>
            {loading ? 'Looking up...' : 'Reverse Lookup'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setIp('');
              setResults([]);
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Hostnames ({results.length})</span>
            <button
              className={styles.copyBtn}
              onClick={() => navigator.clipboard.writeText(results.join('\n'))}
            >
              Copy
            </button>
          </div>
          {results.map((hostname, i) => (
            <div key={i} className={styles.resultItem}>
              <span className={styles.code}>{hostname}</span>
            </div>
          ))}
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>Reverse DNS Use Cases</h3>
        <ul>
          <li>Identify the hostname associated with an IP</li>
          <li>Verify server configurations</li>
          <li>Discover shared hosting environments</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
