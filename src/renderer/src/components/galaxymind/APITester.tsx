import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { PlugIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function APITester() {
  const [method, setMethod] = useState<'GET' | 'POST' | 'PUT' | 'DELETE'>('GET');
  const [url, setUrl] = useState('');
  const [headers, setHeaders] = useState('Content-Type: application/json');
  const [body, setBody] = useState('');
  const [response, setResponse] = useState<{ status: number; body: string; time: number } | null>(
    null
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const sendRequest = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    setLoading(true);
    setError('');
    setResponse(null);

    const startTime = Date.now();

    try {
      const headerObj: Record<string, string> = {};
      headers.split('\n').forEach((h) => {
        const [k, v] = h.split(':').map((s) => s.trim());
        if (k && v) headerObj[k] = v;
      });

      const res = await window.electronAPI.net.httpFetch(url, {
        method,
        headers: headerObj,
        body: method !== 'GET' ? body : undefined,
      });

      setResponse({
        status: res.status || 0,
        body: res.data || res.error || '',
        time: Date.now() - startTime,
      });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="API Tester"
      icon={<PlugIcon />}
      description="Test REST APIs with custom requests"
    >
      <div className={styles.section}>
        <div className={styles.flexRow}>
          <div style={{ width: '100px' }}>
            <label className={styles.label}>Method</label>
            <select
              className={styles.select}
              value={method}
              onChange={(e) => setMethod(e.target.value as 'GET' | 'POST' | 'PUT' | 'DELETE')}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
              <option value="PUT">PUT</option>
              <option value="DELETE">DELETE</option>
            </select>
          </div>
          <div style={{ flex: 1 }}>
            <label className={styles.label}>URL</label>
            <input
              type="text"
              className={styles.input}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://api.example.com/endpoint"
            />
          </div>
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Headers (one per line, Key: Value)</label>
          <textarea
            className={styles.textarea}
            value={headers}
            onChange={(e) => setHeaders(e.target.value)}
            placeholder="Content-Type: application/json"
            style={{ minHeight: '60px' }}
          />
        </div>
        {method !== 'GET' && (
          <div className={styles.inputGroup}>
            <label className={styles.label}>Body</label>
            <textarea
              className={styles.textarea}
              value={body}
              onChange={(e) => setBody(e.target.value)}
              placeholder='{"key": "value"}'
            />
          </div>
        )}
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={sendRequest} disabled={loading}>
            {loading ? 'Sending...' : 'Send Request'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setUrl('');
              setResponse(null);
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {response && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Response</span>
            <span className={response.status < 400 ? styles.badgeSuccess : styles.badgeError}>
              {response.status}
            </span>
            <span style={{ color: 'var(--color-text-tertiary)', fontSize: '12px' }}>
              {response.time}ms
            </span>
          </div>
          <pre className={styles.codeBlock}>{response.body}</pre>
        </div>
      )}
    </ToolWrapper>
  );
}
