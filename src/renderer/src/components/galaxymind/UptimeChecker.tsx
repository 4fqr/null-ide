import React, { useState } from 'react';
import { useStore } from '../../store/store';
import type { HttpResponse } from '../../types/api';
import styles from './SharedTool.module.css';
import { UptimeIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

interface UptimeResult {
  url: string;
  status: number;
  statusText: string;
  responseTime: number;
  timestamp: string;
}

const UptimeChecker: React.FC = () => {
  const { addToolResult } = useStore();
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
      const response = (await window.electronAPI.net.httpFetch(url, {
        method: 'HEAD',
        timeout: 5000,
      })) as HttpResponse;
      const endTime = Date.now();

      if (!response.success) {
        throw new Error(response.error || 'Request failed');
      }

      const status = response.status ?? 0;
      const statusText = response.statusText ?? '';
      const uptimeResult: UptimeResult = {
        url,
        status,
        statusText,
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
        success: status >= 200 && status < 400,
      });
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Check failed';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Uptime Checker"
      icon={<UptimeIcon />}
      description="Monitor website availability and response times"
    >
      <div className={styles.section}>
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
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={checkUptime} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Checking...
              </>
            ) : (
              'Check Uptime'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}
      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Checking website...</span>
        </div>
      )}

      {result && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <div className={styles.resultTitle}>Uptime Status</div>
          </div>
          <div className={styles.resultItem}>
            <div className={styles.resultRow}>
              <span className={styles.resultLabel}>Status</span>
              <span
                className={result.status < 400 ? styles.badgeSuccess : styles.badgeError}
                style={{ padding: '4px 12px', borderRadius: '6px' }}
              >
                {result.status} {result.statusText}
              </span>
            </div>
          </div>
          <div className={styles.resultItem}>
            <div className={styles.resultRow}>
              <span className={styles.resultLabel}>Response Time</span>
              <span className={styles.resultValue}>{result.responseTime}ms</span>
            </div>
          </div>
          <div className={styles.resultItem}>
            <div className={styles.resultRow}>
              <span className={styles.resultLabel}>Checked At</span>
              <span className={styles.resultValue}>
                {new Date(result.timestamp).toLocaleString()}
              </span>
            </div>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default UptimeChecker;
