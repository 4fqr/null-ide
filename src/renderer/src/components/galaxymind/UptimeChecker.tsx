import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

interface UptimeResult {
  url: string;
  status: number;
  statusText: string;
  responseTime: number;
  timestamp: string;
}

const UptimeChecker: React.FC = () => {
  const { setActiveGalaxyTool, addToolResult } = useStore();
  const [url, setUrl] = useState('');
  const [result, setResult] = useState<UptimeResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const checkUptime = async () => {
    if (!url.trim()) {
      setError('URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    const startTime = Date.now();

    try {
      const response: any = await window.electronAPI.net.httpFetch(url, { method: 'HEAD', timeout: 5000 });
      const endTime = Date.now();

      if (!response.success) {
        throw new Error(response.error || 'Request failed');
      }

      const uptimeResult: UptimeResult = {
        url,
        status: response.status,
        statusText: response.statusText,
        responseTime: endTime - startTime,
        timestamp: new Date().toISOString(),
      };

      setResult(uptimeResult);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Uptime Checker',
        timestamp: Date.now(),
        input: { url },
        output: uptimeResult,
        success: response.status >= 200 && response.status < 400,
      });
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Check failed';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <h2 className={styles.toolTitle}>
          <span className={styles.toolIcon}>⏱️</span>
          Uptime Checker
        </h2>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Website URL</label>
            <input
              type="text"
              className={styles.input}
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </div>

          <button className={styles.sendButton} onClick={checkUptime} disabled={loading}>
            {loading ? 'Checking...' : 'Check Uptime'}
          </button>
        </div>

        {error && (
          <div className={styles.error}>
            <strong>Error:</strong> {error}
          </div>
        )}

        {loading && (
          <div className={styles.loading}>
            <div className={styles.spinner}></div>
            <span>Checking website...</span>
          </div>
        )}

        {result && (
          <div className={styles.results}>
            <h3 className={styles.sectionTitle}>Uptime Status</h3>
            <div className={styles.resultItem}>
              <strong style={{ color: '#00ffaa' }}>Status:</strong>
              <span
                style={{
                  marginLeft: '8px',
                  padding: '4px 12px',
                  borderRadius: '6px',
                  fontWeight: '700',
                  background: result.status < 400 ? 'rgba(76, 175, 80, 0.2)' : 'rgba(244, 67, 54, 0.2)',
                  color: result.status < 400 ? '#4caf50' : '#f44336',
                  border: `1px solid ${result.status < 400 ? '#4caf50' : '#f44336'}`,
                }}
              >
                {result.status} {result.statusText}
              </span>
            </div>
            <div className={styles.resultItem}>
              <strong style={{ color: '#00ffaa' }}>Response Time:</strong>
              <span style={{ color: '#e0e0ff', marginLeft: '8px' }}>{result.responseTime}ms</span>
            </div>
            <div className={styles.resultItem}>
              <strong style={{ color: '#00ffaa' }}>Checked At:</strong>
              <span style={{ color: '#e0e0ff', marginLeft: '8px' }}>{new Date(result.timestamp).toLocaleString()}</span>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default UptimeChecker;
