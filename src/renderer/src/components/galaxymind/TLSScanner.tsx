import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { ShieldIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

const TLSScanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [host, setHost] = useState('');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testTLS = async () => {
    if (!host.trim()) {
      setError('Host is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ test: string; result: string }> = [];

      try {
        const result = await window.electronAPI.net.httpFetch(`https://${host}`, {
          method: 'GET',
          timeout: 5000,
        });
        found.push({
          test: 'HTTPS',
          result: result.status === 200 ? 'Supported' : `Status: ${result.status}`,
        });
      } catch (err) {
        found.push({ test: 'HTTPS', result: 'Failed' });
      }

      const versions = ['TLS 1.0', 'TLS 1.1', 'TLS 1.2', 'TLS 1.3'];
      for (const version of versions) {
        found.push({ test: version, result: 'Requires manual testing' });
      }

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'TLS Scanner',
        timestamp: Date.now(),
        input: { host },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'TLS scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="TLS/SSL Scanner"
      icon={<ShieldIcon />}
      description="Analyze TLS/SSL configuration and security"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Host</label>
          <input
            type="text"
            className={styles.input}
            placeholder="example.com"
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testTLS} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan TLS'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}
      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing TLS configuration...</span>
        </div>
      )}
      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <div className={styles.resultTitle}>TLS Test Results</div>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div className={styles.resultRow}>
                <span className={styles.resultLabel}>{result.test}</span>
                <span className={styles.resultValue}>{result.result}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default TLSScanner;
