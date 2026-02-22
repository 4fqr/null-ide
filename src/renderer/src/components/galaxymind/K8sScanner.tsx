import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { ServerIcon, LoadingIcon } from '../common/Icons';

const K8sScanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [targetHost, setTargetHost] = useState('');
  const [port, setPort] = useState('8080');
  const [results, setResults] = useState<Array<{ endpoint: string; status: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testK8s = async () => {
    if (!targetHost.trim()) {
      setError('Target host is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ endpoint: string; status: string }> = [];
      const endpoints = [
        '/api',
        '/api/v1',
        '/api/v1/pods',
        '/api/v1/namespaces',
        '/api/v1/secrets',
      ];

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

      const secureUrl = `https://${targetHost}:6443/api`;
      try {
        const result = await window.electronAPI.net.httpFetch(secureUrl, {
          method: 'GET',
          timeout: 5000,
        });
        found.push({
          endpoint: '/api (6443)',
          status: result.status === 401 ? 'Auth Required' : 'EXPOSED!',
        });
      } catch {
        found.push({ endpoint: '/api (6443)', status: 'Not Accessible' });
      }

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Kubernetes Scanner',
        timestamp: Date.now(),
        input: { targetHost, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'K8s scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Kubernetes API Scanner"
      icon={<ServerIcon />}
      description="Scan for exposed Kubernetes API endpoints"
    >
      <div className={styles.section}>
        <div className={styles.flexRow}>
          <div className={styles.flex1}>
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
          </div>
          <div className={styles.flex1}>
            <div className={styles.inputGroup}>
              <label className={styles.label}>Port</label>
              <input
                type="text"
                className={styles.input}
                placeholder="8080"
                value={port}
                onChange={(e) => setPort(e.target.value)}
              />
            </div>
          </div>
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testK8s} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan K8s API'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing Kubernetes API endpoints...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Kubernetes API Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span className={styles.textSuccess}>{result.endpoint}</span>
              <span
                className={styles.ml8}
                style={{ color: result.status.includes('EXPOSED') ? '#ff6b8a' : '#888' }}
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

export default K8sScanner;
