import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ServerIcon, LoadingIcon } from '../common/Icons';

const EtcdScanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('2379');
  const [results, setResults] = useState<Array<{ endpoint: string; status: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testEtcd = async () => {
    if (!host.trim()) {
      setError('Host is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ endpoint: string; status: string }> = [];
      const endpoints = ['/version', '/v2/keys', '/v3/kv/range'];

      for (const endpoint of endpoints) {
        try {
          const result = await window.electronAPI.net.httpFetch(
            `http://${host}:${port}${endpoint}`,
            {
              method: 'GET',
              timeout: 5000,
            }
          );
          found.push({
            endpoint,
            status: result.status === 200 ? 'EXPOSED!' : `Status: ${result.status}`,
          });
        } catch {
          found.push({ endpoint, status: 'Not Accessible' });
        }
        await new Promise((resolve) => setTimeout(resolve, 200));
      }

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'etcd Scanner',
        timestamp: Date.now(),
        input: { host, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'etcd scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="etcd Scanner"
      icon={<ServerIcon />}
      description="Scan etcd endpoints for exposed keys and sensitive data"
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
            placeholder="2379"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testEtcd} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan etcd'
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
          <span>Testing etcd...</span>
        </div>
      )}
      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>etcd Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.endpoint}
              </span>
              <span
                style={{
                  color: result.status.includes('EXPOSED') ? '#ff4444' : '#888',
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
};

export default EtcdScanner;
