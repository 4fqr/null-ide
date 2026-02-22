import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { LockIcon, LoadingIcon } from '../common/Icons';

export default function AuthzBypass() {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [userId, setUserId] = useState('1');
  const [results, setResults] = useState<Array<{ attack: string; url: string; status: string }>>(
    []
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testAuthz = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ attack: string; url: string; status: string }> = [];

      const idorTests = ['2', '0', '-1', '999999', 'admin'];
      for (const testId of idorTests) {
        const testUrl = targetUrl.replace(userId, testId);
        try {
          const result = await window.electronAPI.net.httpFetch(testUrl, {
            method: 'GET',
            timeout: 5000,
          });

          const vulnerable = result.status === 200;
          found.push({
            attack: 'IDOR',
            url: testUrl,
            status: vulnerable ? 'VULNERABLE!' : `Blocked (${result.status})`,
          });
        } catch {
          found.push({ attack: 'IDOR', url: testUrl, status: 'Error' });
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }

      const traversalPayloads = ['../admin', '../../admin', '../../../etc/passwd'];
      for (const payload of traversalPayloads) {
        const testUrl = `${targetUrl}/${payload}`;
        try {
          const result = await window.electronAPI.net.httpFetch(testUrl, {
            method: 'GET',
            timeout: 5000,
          });

          const vulnerable = result.status === 200;
          found.push({
            attack: 'Path Traversal',
            url: testUrl,
            status: vulnerable ? 'VULNERABLE!' : `Blocked (${result.status})`,
          });
        } catch {
          found.push({ attack: 'Path Traversal', url: testUrl, status: 'Blocked' });
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }

      const methods = ['PUT', 'DELETE', 'PATCH'];
      for (const method of methods) {
        try {
          const result = await window.electronAPI.net.httpFetch(targetUrl, {
            method: method as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH',
            timeout: 5000,
          });

          const vulnerable = result.status === 200;
          found.push({
            attack: `HTTP ${method}`,
            url: targetUrl,
            status: vulnerable ? 'ALLOWED (Check perms)' : `Blocked (${result.status})`,
          });
        } catch {
          found.push({ attack: `HTTP ${method}`, url: targetUrl, status: 'Blocked' });
        }
        await new Promise((resolve) => setTimeout(resolve, 100));
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Authorization Bypass',
        timestamp: Date.now(),
        input: { targetUrl, userId },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Authorization test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Authorization Bypass Scanner"
      icon={<LockIcon />}
      description="Test authorization controls for bypass vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/api/user/1"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Current User ID</label>
          <input
            type="text"
            className={styles.input}
            placeholder="1"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testAuthz} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test Authorization'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing authorization bypass...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Authorization Test Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div>
                <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                  {result.attack}
                </span>
                <span
                  style={{
                    color:
                      result.status.includes('VULNERABLE') || result.status.includes('ALLOWED')
                        ? '#ff4444'
                        : '#888',
                    marginLeft: '10px',
                  }}
                >
                  {result.status}
                </span>
              </div>
              <span style={{ color: '#666', fontSize: '10px', marginTop: '2px', display: 'block' }}>
                {result.url}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
