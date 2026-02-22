import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { NetworkIcon } from '../common/Icons';

const HTTP2Scanner: React.FC = () => {
  const addToolResult = useStore((state) => state.addToolResult);
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testHTTP2 = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ test: string; result: string }> = [];

      try {
        const result = await window.electronAPI.net.httpFetch(targetUrl, {
          method: 'GET',
          timeout: 5000,
        });

        const headers = JSON.stringify(result.headers || {});
        const supportsHTTP2 =
          headers.toLowerCase().includes('http/2') || headers.toLowerCase().includes('h2');
        found.push({
          test: 'HTTP/2 Support',
          result: supportsHTTP2 ? 'Supported' : 'Not Supported',
        });
      } catch {
        found.push({ test: 'HTTP/2 Support', result: 'Error' });
      }

      found.push({ test: 'Server Push', result: 'Manual inspection required' });

      const smugglingPayloads = [
        {
          name: 'Content-Length',
          headers: { 'Content-Length': '0', 'Transfer-Encoding': 'chunked' },
        },
        { name: 'Duplicate Headers', headers: { Host: 'evil.com' } },
      ] as const;

      for (const payload of smugglingPayloads) {
        try {
          await window.electronAPI.net.httpFetch(targetUrl, {
            method: 'POST',
            headers: payload.headers,
            timeout: 3000,
          });
          found.push({ test: `Smuggling: ${payload.name}`, result: 'Request Accepted' });
        } catch {
          found.push({ test: `Smuggling: ${payload.name}`, result: 'Blocked' });
        }
      }

      found.push({ test: 'HPACK Bomb Protection', result: 'Manual test required' });

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'HTTP/2 Scanner',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'HTTP/2 test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="HTTP/2 Security Scanner"
      icon={<NetworkIcon />}
      description="Scan for HTTP/2 vulnerabilities and configuration issues"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testHTTP2} disabled={loading}>
            {loading ? 'Scanning...' : 'Scan HTTP/2'}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing HTTP/2 configuration...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <div className={styles.resultTitle}>HTTP/2 Test Results</div>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div className={styles.resultRow}>
                <span className={styles.resultLabel}>{result.test}</span>
                <span className={styles.resultValue}>{result.result}</span>
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default HTTP2Scanner;
