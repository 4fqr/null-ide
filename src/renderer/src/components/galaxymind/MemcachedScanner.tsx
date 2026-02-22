import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { DatabaseIcon, LoadingIcon } from '../common/Icons';

const MemcachedScanner: React.FC = () => {
  const addToolResult = useStore((state) => state.addToolResult);
  const [host, setHost] = useState('');
  const [port, setPort] = useState('11211');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testMemcached = async () => {
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

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Memcached Scanner',
        timestamp: Date.now(),
        input: { host, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Memcached scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Memcached Scanner"
      icon={<DatabaseIcon />}
      description="Scan for exposed Memcached instances"
    >
      <div className={styles.section}>
        <div className={styles.flexRow}>
          <div className={styles.flex1}>
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
          </div>
          <div style={{ width: '150px' }}>
            <div className={styles.inputGroup}>
              <label className={styles.label}>Port</label>
              <input
                type="text"
                className={styles.input}
                placeholder="11211"
                value={port}
                onChange={(e) => setPort(e.target.value)}
              />
            </div>
          </div>
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testMemcached} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan Memcached'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing Memcached...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultTitle}>Memcached Results</div>
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

export default MemcachedScanner;
