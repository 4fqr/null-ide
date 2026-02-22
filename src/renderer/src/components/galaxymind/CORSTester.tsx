import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { NetworkIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function CORSTester() {
  const [url, setUrl] = useState('');
  const [origin, setOrigin] = useState('https://evil.com');
  const [results, setResults] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const test = async () => {
    if (!url.trim()) {
      setError('Please enter a target URL');
      return;
    }

    setLoading(true);
    setError('');
    setResults([]);

    const testResults: string[] = [];

    try {
      const res = await window.electronAPI.net.httpFetch(url, {
        method: 'GET',
        headers: { Origin: origin },
      });

      const acao = res.headers?.['access-control-allow-origin'];
      const acac = res.headers?.['access-control-allow-credentials'];

      testResults.push(`Status: ${res.status}`);
      testResults.push(`ACAO: ${acao || 'Not set'}`);
      testResults.push(`ACAC: ${acac || 'Not set'}`);

      if (acao === '*') {
        testResults.push('VULNERABLE: Wildcard (*) allows any origin!');
      } else if (acao === origin) {
        testResults.push('VULNERABLE: Origin is reflected without validation!');
      } else if (acao === 'null') {
        testResults.push('VULNERABLE: Null origin allowed!');
      } else {
        testResults.push('SAFE: No CORS vulnerability detected');
      }
    } catch (err) {
      testResults.push(`Error: ${(err as Error).message}`);
    }

    setResults(testResults);
    setLoading(false);
  };

  return (
    <ToolWrapper
      title="CORS Tester"
      icon={<NetworkIcon />}
      description="Test CORS misconfigurations"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://api.example.com"
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Test Origin</label>
          <input
            type="text"
            className={styles.input}
            value={origin}
            onChange={(e) => setOrigin(e.target.value)}
            placeholder="https://evil.com"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={test} disabled={loading}>
            {loading ? 'Testing...' : 'Test CORS'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setUrl('');
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
            <span className={styles.resultTitle}>Results</span>
          </div>
          {results.map((r, i) => (
            <div key={i} className={styles.resultItem}>
              <span
                className={
                  r.includes('VULNERABLE')
                    ? styles.badgeError
                    : r.includes('SAFE')
                      ? styles.badgeSuccess
                      : ''
                }
              >
                {r}
              </span>
            </div>
          ))}
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>CORS Misconfigurations</h3>
        <ul>
          <li>
            <strong>Wildcard (*):</strong> Allows any origin
          </li>
          <li>
            <strong>Reflected Origin:</strong> Origin echoed without validation
          </li>
          <li>
            <strong>Null Origin:</strong> Allows sandbox iframes
          </li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
