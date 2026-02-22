import { useState } from 'react';
import { DatabaseIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

interface CookieAnalysis {
  name: string;
  value: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string;
  domain: string;
  path: string;
  issues: string[];
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
}

export default function CookieAnalyzer() {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<CookieAnalysis[]>([]);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState('');

  const analyzeCookies = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    try {
      setIsAnalyzing(true);
      setError('');
      setResults([]);

      const targetUrl = url.startsWith('http') ? url : `https://${url}`;
      const response = await window.electronAPI.net.httpFetch(targetUrl, {
        method: 'GET',
        timeout: 10000,
      });

      const setCookieHeader = response.headers?.['set-cookie'];
      if (!setCookieHeader) {
        setError('No Set-Cookie headers found');
        setIsAnalyzing(false);
        return;
      }

      const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader];
      const analyses: CookieAnalysis[] = [];

      for (const cookie of cookies) {
        const parts = cookie.split(';').map((p: string) => p.trim());
        const [nameValue] = parts;
        const [name, value] = nameValue.split('=');

        const secure = parts.some((p: string) => p.toLowerCase() === 'secure');
        const httpOnly = parts.some((p: string) => p.toLowerCase() === 'httponly');
        const sameSitePart = parts.find((p: string) => p.toLowerCase().startsWith('samesite='));
        const sameSite = sameSitePart ? sameSitePart.split('=')[1] : 'None';
        const domainPart = parts.find((p: string) => p.toLowerCase().startsWith('domain='));
        const domain = domainPart ? domainPart.split('=')[1] : 'current domain';
        const pathPart = parts.find((p: string) => p.toLowerCase().startsWith('path='));
        const path = pathPart ? pathPart.split('=')[1] : '/';

        const issues: string[] = [];
        let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';

        if (!secure && targetUrl.startsWith('https://')) {
          issues.push('Missing Secure flag - cookie can be sent over HTTP');
          risk = 'High';
        }

        if (!httpOnly) {
          issues.push('Missing HttpOnly flag - vulnerable to XSS cookie theft');
          if (risk === 'Low') risk = 'Medium';
        }

        if (sameSite.toLowerCase() === 'none' || !sameSitePart) {
          issues.push('SameSite=None or missing - vulnerable to CSRF attacks');
          if (risk === 'Low' || risk === 'Medium') risk = 'High';
        }

        const sensitiveNames = ['session', 'auth', 'token', 'jwt', 'password', 'key'];
        const isSensitive = sensitiveNames.some((s) => name.toLowerCase().includes(s));

        if (isSensitive && (!secure || !httpOnly)) {
          issues.push('Sensitive cookie with weak security flags');
          risk = 'Critical';
        }

        if (domain.startsWith('.')) {
          issues.push(`Cookie accessible to all subdomains (${domain})`);
        }

        if (path === '/') {
          issues.push('Cookie accessible site-wide (Path=/)');
        }

        if (issues.length === 0) {
          issues.push('Cookie appears properly secured');
        }

        analyses.push({
          name,
          value: value.substring(0, 20) + (value.length > 20 ? '...' : ''),
          secure,
          httpOnly,
          sameSite,
          domain,
          path,
          issues,
          risk,
        });
      }

      setResults(analyses);
    } catch (err) {
      setError(`Analysis error: ${(err as Error).message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  return (
    <ToolWrapper
      title="Cookie Security Analyzer"
      icon={<DatabaseIcon />}
      description="Analyze cookie security settings and identify vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className={styles.input}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button onClick={analyzeCookies} disabled={isAnalyzing} className={styles.primaryBtn}>
            {isAnalyzing ? 'ANALYZING...' : 'ANALYZE COOKIES'}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>
              Cookie Analysis (
              {results.filter((r) => r.risk === 'Critical' || r.risk === 'High').length} critical
              issues)
            </span>
          </div>

          {results.map((result, idx) => (
            <div
              key={idx}
              className={styles.resultItem}
              style={{
                borderLeft:
                  result.risk === 'Critical'
                    ? '3px solid #ff6b8a'
                    : result.risk === 'High'
                      ? '3px solid #ff3366'
                      : result.risk === 'Medium'
                        ? '3px solid #ffaa00'
                        : undefined,
              }}
            >
              <div
                className={styles.flexRow}
                style={{ justifyContent: 'space-between', marginBottom: '10px' }}
              >
                <span style={{ fontWeight: 'bold', fontSize: '16px' }}>{result.name}</span>
                <span
                  className={
                    result.risk === 'Critical'
                      ? styles.badgeCritical
                      : result.risk === 'High'
                        ? styles.badgeHigh
                        : result.risk === 'Medium'
                          ? styles.badgeMedium
                          : styles.badgeLow
                  }
                >
                  {result.risk}
                </span>
              </div>

              <div className={styles.grid2} style={{ marginBottom: '10px' }}>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)', fontSize: '12px' }}>
                    Secure:{' '}
                  </span>
                  <span style={{ color: result.secure ? '#00ff88' : '#ff6b8a' }}>
                    {result.secure ? 'Yes' : 'No'}
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)', fontSize: '12px' }}>
                    HttpOnly:{' '}
                  </span>
                  <span style={{ color: result.httpOnly ? '#00ff88' : '#ff6b8a' }}>
                    {result.httpOnly ? 'Yes' : 'No'}
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)', fontSize: '12px' }}>
                    SameSite:{' '}
                  </span>
                  <span>{result.sameSite}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)', fontSize: '12px' }}>
                    Path:{' '}
                  </span>
                  <span>{result.path}</span>
                </div>
              </div>

              <div
                style={{
                  color: 'var(--color-text-tertiary)',
                  fontSize: '12px',
                  marginBottom: '8px',
                }}
              >
                Domain: {result.domain}
              </div>

              <div style={{ marginTop: '10px' }}>
                {result.issues.map((issue, issueIdx) => (
                  <div
                    key={issueIdx}
                    className={styles.warningBox}
                    style={{ marginBottom: '5px', fontSize: '13px' }}
                  >
                    {issue}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
