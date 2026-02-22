import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ServerIcon, LoadingIcon } from '../common/Icons';

export default function ConsulScanner() {
  const { addToolResult } = useStore();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('8500');
  const [results, setResults] = useState<Array<{ endpoint: string; status: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testConsul = async () => {
    if (!host.trim()) {
      setError('Host is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ endpoint: string; status: string }> = [];
      const endpoints = ['/v1/agent/self', '/v1/catalog/services', '/v1/kv/'];

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
        toolName: 'Consul Scanner',
        timestamp: Date.now(),
        input: { host, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Consul scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Consul Scanner"
      icon={<ServerIcon />}
      description="Scan for exposed Consul service discovery endpoints"
    >
      <div className={styles.section}>
        <div className={styles.grid2}>
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
              placeholder="8500"
              value={port}
              onChange={(e) => setPort(e.target.value)}
            />
          </div>
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testConsul} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan Consul'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing Consul...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Consul Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.endpoint}
              </span>
              <span
                style={{
                  color: result.status.includes('EXPOSED') ? '#ff6b8a' : '#888',
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
