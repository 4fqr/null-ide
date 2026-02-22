import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

export default function DeserializationScanner() {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<
    Array<{ type: string; indicator: string; found: boolean }>
  >([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const deserializationTests = [
    { type: 'Java Serialized', indicator: 'rO0AB', header: 'application/x-java-serialized-object' },
    { type: 'Python Pickle', indicator: '\x80\x03', header: 'application/python-pickle' },
    { type: 'PHP Serialize', indicator: 'O:', header: 'application/vnd.php.serialized' },
    { type: '.NET ViewState', indicator: '/wEP', header: 'application/x-viewstate' },
    { type: 'Ruby Marshal', indicator: '\x04\x08', header: 'application/x-ruby-marshal' },
  ];

  const testDeserialization = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ type: string; indicator: string; found: boolean }> = [];

      for (const { type, indicator, header } of deserializationTests) {
        try {
          const result = await window.electronAPI.net.httpFetch(targetUrl, {
            method: 'GET',
            timeout: 5000,
          });

          const bodyStr = result.data || '';
          const headersStr = JSON.stringify(result.headers || {});

          const hasIndicator = bodyStr.includes(indicator) || headersStr.includes(header);
          found.push({ type, indicator, found: hasIndicator });
        } catch {
          found.push({ type, indicator, found: false });
        }

        await new Promise((resolve) => setTimeout(resolve, 200));
      }

      const gadgetPayloads = ['aced0005737200', 'O:8:"stdClass":'];

      for (const payload of gadgetPayloads) {
        try {
          await window.electronAPI.net.httpFetch(targetUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/octet-stream' },
            body: payload,
            timeout: 3000,
          });
        } catch {
          void 0;
        }
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Deserialization Scanner',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Deserialization test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Deserialization Scanner"
      icon={<ShieldIcon />}
      description="Scan for unsafe deserialization vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/api"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testDeserialization} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan for Deserialization'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing deserialization vulnerabilities...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Deserialization Indicators</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.type}
              </span>
              <span style={{ color: result.found ? '#ff6b8a' : '#888', marginLeft: '10px' }}>
                {result.found ? 'FOUND!' : 'Not Detected'}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
