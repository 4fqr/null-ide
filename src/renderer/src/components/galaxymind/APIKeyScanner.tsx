import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { SearchIcon, LoadingIcon } from '../common/Icons';

export default function APIKeyScanner() {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<Array<{ source: string; keys: string[] }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const keyPatterns = [
    { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g },
    { name: 'AWS Secret Key', regex: /aws(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]/ },
    { name: 'GitHub Token', regex: /gh[pousr]_[0-9a-zA-Z]{36}/g },
    { name: 'Google API Key', regex: /AIza[0-9A-Za-z\-_]{35}/g },
    { name: 'Slack Token', regex: /xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[0-9a-zA-Z]{24,32}/g },
    { name: 'Stripe Key', regex: /sk_live_[0-9a-zA-Z]{24}/g },
    { name: 'Square Token', regex: /sq0atp-[0-9A-Za-z\-_]{22}/g },
    { name: 'PayPal Token', regex: /access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}/g },
  ];

  const scanForKeys = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ source: string; keys: string[] }> = [];

      const result = await window.electronAPI.net.httpFetch(targetUrl, {
        method: 'GET',
        timeout: 5000,
      });

      const html = String(result);

      const htmlKeys: string[] = [];
      for (const pattern of keyPatterns) {
        const matches = html.match(pattern.regex);
        if (matches) {
          htmlKeys.push(`${pattern.name}: ${matches[0]}`);
        }
      }
      if (htmlKeys.length > 0) {
        found.push({ source: 'HTML Source', keys: htmlKeys });
      }

      const jsFiles = ['/main.js', '/app.js', '/bundle.js', '/config.js'];
      const baseUrl = new URL(targetUrl);

      for (const jsFile of jsFiles) {
        try {
          const jsUrl = `${baseUrl.origin}${jsFile}`;
          const jsResult = await window.electronAPI.net.httpFetch(jsUrl, {
            method: 'GET',
            timeout: 3000,
          });

          const jsContent = String(jsResult);
          const jsKeys: string[] = [];

          for (const pattern of keyPatterns) {
            const matches = jsContent.match(pattern.regex);
            if (matches) {
              jsKeys.push(`${pattern.name}: ${matches[0]}`);
            }
          }

          if (jsKeys.length > 0) {
            found.push({ source: jsFile, keys: jsKeys });
          }
        } catch {
          void 0;
        }
      }

      if (found.length === 0) {
        found.push({ source: 'No keys found', keys: [] });
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'API Key Scanner',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'API key scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="API Key Leakage Scanner"
      icon={<SearchIcon />}
      description="Scan websites for exposed API keys and secrets"
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
          <button className={styles.primaryBtn} onClick={scanForKeys} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan for API Keys'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Scanning for exposed API keys...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Scan Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.source}
              </span>
              {result.keys.length > 0 ? (
                result.keys.map((key, kidx) => (
                  <span
                    key={kidx}
                    style={{
                      color: '#ff4444',
                      fontSize: '11px',
                      marginLeft: '10px',
                      marginTop: '2px',
                      display: 'block',
                    }}
                  >
                    FOUND: {key}
                  </span>
                ))
              ) : (
                <span style={{ color: '#888', fontSize: '11px', marginLeft: '10px' }}>Clean</span>
              )}
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
