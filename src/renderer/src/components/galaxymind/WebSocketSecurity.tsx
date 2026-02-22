import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { NetworkIcon, LoadingIcon } from '../common/Icons';

const WebSocketSecurity: React.FC = () => {
  const { addToolResult } = useStore();
  const [wsUrl, setWsUrl] = useState('');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testWebSocket = async () => {
    if (!wsUrl.trim()) {
      setError('WebSocket URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ test: string; result: string }> = [];

      const httpUrl = wsUrl.replace('wss://', 'https://').replace('ws://', 'http://');
      try {
        const result = await window.electronAPI.net.httpFetch(httpUrl, {
          method: 'GET',
          timeout: 5000,
        });

        const hasWsHeaders = JSON.stringify(result.headers || {})
          .toLowerCase()
          .includes('upgrade');
        found.push({
          test: 'WebSocket Endpoint Detection',
          result: hasWsHeaders ? 'Found' : 'Not Found',
        });
      } catch {
        found.push({ test: 'WebSocket Endpoint Detection', result: 'Error' });
      }

      try {
        const result = await window.electronAPI.net.httpFetch(httpUrl, {
          method: 'GET',
          headers: { Origin: 'https://evil.com' },
          timeout: 5000,
        });

        const headers = JSON.stringify(result.headers || {});
        const allowsAnyOrigin =
          headers.includes('Access-Control-Allow-Origin: *') || headers.includes('evil.com');
        found.push({
          test: 'CORS Policy',
          result: allowsAnyOrigin ? 'VULNERABLE (allows any origin)' : 'Restricted',
        });
      } catch {
        found.push({ test: 'CORS Policy', result: 'Error' });
      }

      found.push({
        test: 'Authentication Check',
        result: 'Manual WebSocket connection required',
      });

      const startTime = Date.now();
      try {
        for (let i = 0; i < 5; i++) {
          await window.electronAPI.net.httpFetch(httpUrl, {
            method: 'GET',
            timeout: 2000,
          });
        }
        const duration = Date.now() - startTime;
        found.push({
          test: 'Rate Limiting',
          result: duration < 1000 ? 'NOT PROTECTED' : 'Likely Protected',
        });
      } catch {
        found.push({ test: 'Rate Limiting', result: 'Connection Blocked' });
      }

      const isSecure = wsUrl.startsWith('wss://') || wsUrl.startsWith('https://');
      found.push({
        test: 'Encryption (WSS)',
        result: isSecure ? 'Secure (WSS)' : 'INSECURE (WS)',
      });

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'WebSocket Security',
        timestamp: Date.now(),
        input: { wsUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'WebSocket test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="WebSocket Security Tester"
      icon={<NetworkIcon />}
      description="Analyze WebSocket endpoints for security vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>WebSocket URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="wss://example.com/ws"
            value={wsUrl}
            onChange={(e) => setWsUrl(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testWebSocket} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test WebSocket'
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
          <span>Testing WebSocket security...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>WebSocket Security Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.test}
              </span>
              <span
                style={{
                  color:
                    result.result.includes('VULNERABLE') ||
                    result.result.includes('INSECURE') ||
                    result.result.includes('NOT PROTECTED')
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

export default WebSocketSecurity;
