import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { DatabaseIcon, LoadingIcon } from '../common/Icons';

const MongoScanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('27017');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testMongo = async () => {
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
        found.push({ test: 'Port Status', result: result.open ? 'OPEN' : 'Closed' });
      } catch {
        found.push({ test: 'Port Status', result: 'Error' });
      }

      try {
        const result = await window.electronAPI.net.httpFetch(`http://${host}:${port}`, {
          method: 'GET',
          timeout: 3000,
        });
        const msg = String(result).toLowerCase();
        if (msg.includes('mongo') || msg.includes('unauthorized')) {
          found.push({ test: 'HTTP Interface', result: 'EXPOSED!' });
        }
      } catch {
        found.push({ test: 'HTTP Interface', result: 'Not accessible' });
      }

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'MongoDB Scanner',
        timestamp: Date.now(),
        input: { host, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'MongoDB scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="MongoDB Scanner"
      icon={<DatabaseIcon />}
      description="Scan MongoDB instances for security vulnerabilities"
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
        <div className={styles.inputGroup}>
          <label className={styles.label}>Port</label>
          <input
            type="text"
            className={styles.input}
            placeholder="27017"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testMongo} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan MongoDB'
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className={styles.errorBox}>
          <strong>Error:</strong> {error}
        </div>
      )}
      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing MongoDB...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <h3 className={styles.resultTitle}>MongoDB Scan Results</h3>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.test}
              </span>
              <span
                style={{
                  color:
                    result.result.includes('OPEN') || result.result.includes('EXPOSED')
                      ? '#ff4444'
                      : '#888',
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

export default MongoScanner;
