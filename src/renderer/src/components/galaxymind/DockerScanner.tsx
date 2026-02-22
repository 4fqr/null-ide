import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ServerIcon, LoadingIcon } from '../common/Icons';

export default function DockerScanner() {
  const { addToolResult } = useStore();
  const [targetHost, setTargetHost] = useState('');
  const [port, setPort] = useState('2375');
  const [results, setResults] = useState<Array<{ endpoint: string; status: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testDocker = async () => {
    if (!targetHost.trim()) {
      setError('Target host is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ endpoint: string; status: string }> = [];
      const endpoints = ['/version', '/info', '/containers/json', '/images/json'];

      for (const endpoint of endpoints) {
        const url = `http://${targetHost}:${port}${endpoint}`;
        try {
          const result = await window.electronAPI.net.httpFetch(url, {
            method: 'GET',
            timeout: 5000,
          });

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
        toolName: 'Docker Scanner',
        timestamp: Date.now(),
        input: { targetHost, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Docker scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Docker API Scanner"
      icon={<ServerIcon />}
      description="Scan for exposed Docker API endpoints"
    >
      <div className={styles.section}>
        <div className={styles.grid2}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Target Host</label>
            <input
              type="text"
              className={styles.input}
              placeholder="example.com"
              value={targetHost}
              onChange={(e) => setTargetHost(e.target.value)}
            />
          </div>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Port</label>
            <input
              type="text"
              className={styles.input}
              placeholder="2375"
              value={port}
              onChange={(e) => setPort(e.target.value)}
            />
          </div>
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testDocker} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan Docker API'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing Docker API endpoints...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Docker API Results</span>
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
