import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { DatabaseIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

const RedisScanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('6379');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testRedis = async () => {
    if (!host.trim()) {
      setError('Host is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ test: string; result: string }> = [];
      const portNum = parseInt(port);

      try {
        const result = await window.electronAPI.net.scanPort(host, portNum);
        found.push({ test: 'Port Status', result: result.isOpen ? 'OPEN' : 'Closed' });
      } catch {
        found.push({ test: 'Port Status', result: 'Error' });
      }

      try {
        const result = await window.electronAPI.net.httpFetch(`http://${host}:${port}`, {
          method: 'GET',
          timeout: 3000,
        });
        found.push({ test: 'HTTP Access', result: `Status: ${result.status}` });
      } catch {
        found.push({ test: 'HTTP Access', result: 'Not accessible via HTTP' });
      }

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Redis Scanner',
        timestamp: Date.now(),
        input: { host, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Redis scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Redis Scanner"
      icon={<DatabaseIcon />}
      description="Scan for Redis service availability"
    >
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
      <div className={styles.inputGroup}>
        <label className={styles.label}>Port</label>
        <input
          type="text"
          className={styles.input}
          placeholder="6379"
          value={port}
          onChange={(e) => setPort(e.target.value)}
        />
      </div>
      <button className={styles.primaryBtn} onClick={testRedis} disabled={loading}>
        {loading ? (
          <>
            <LoadingIcon /> Scanning...
          </>
        ) : (
          'Scan Redis'
        )}
      </button>

      {error && <div className={styles.errorBox}>{error}</div>}
      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing Redis...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Redis Scan Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.test}
              </span>
              <span
                style={{
                  color: result.result.includes('OPEN') ? '#ff4444' : '#888',
                  marginLeft: '10px',
                }}
              >
                {result.result}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default RedisScanner;
