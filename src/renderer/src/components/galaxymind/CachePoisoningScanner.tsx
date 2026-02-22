import { useState } from 'react';
import { ShieldIcon, LoadingIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

interface CachePoisonResult {
  technique: string;
  description: string;
  headers: Record<string, string>;
  statusCode: number;
  cacheHeaders: Record<string, string>;
  vulnerable: boolean;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  details: string;
}

export default function CachePoisoningScanner() {
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<CachePoisonResult[]>([]);

  const cachePoisonTechniques: Array<{
    name: string;
    headers: Record<string, string>;
    desc: string;
  }> = [
    {
      name: 'X-Forwarded-Host',
      headers: { 'X-Forwarded-Host': 'evil.com' },
      desc: 'Attempt to poison cached content with malicious host',
    },
    {
      name: 'X-Forwarded-Scheme',
      headers: { 'X-Forwarded-Scheme': 'http' },
      desc: 'Force HTTP scheme in cached content',
    },
    {
      name: 'X-Original-URL',
      headers: { 'X-Original-URL': '/admin' },
      desc: 'Override URL path in cache',
    },
    {
      name: 'X-Rewrite-URL',
      headers: { 'X-Rewrite-URL': '/admin' },
      desc: 'Rewrite URL to access protected resources',
    },
    {
      name: 'X-Forwarded-Server',
      headers: { 'X-Forwarded-Server': 'malicious.example.com' },
      desc: 'Inject malicious server name',
    },
    {
      name: 'X-Host',
      headers: { 'X-Host': 'attacker.com' },
      desc: 'Alternative host header poisoning',
    },
    {
      name: 'Forwarded',
      headers: { Forwarded: 'host=evil.com;proto=http' },
      desc: 'RFC 7239 Forwarded header poisoning',
    },
    {
      name: 'X-HTTP-Method-Override',
      headers: { 'X-HTTP-Method-Override': 'POST' },
      desc: 'Override HTTP method in cached response',
    },
  ];

  const testCachePoisoning = async () => {
    if (!targetUrl) return;

    setLoading(true);
    setResults([]);

    const testResults: CachePoisonResult[] = [];

    for (const technique of cachePoisonTechniques) {
      try {
        const response = await window.electronAPI.net.httpFetch(targetUrl, {
          method: 'GET',
          headers: technique.headers,
          timeout: 5000,
        });

        const cacheHeaders: Record<string, string> = {};
        if (response.headers) {
          Object.entries(response.headers).forEach(([key, value]) => {
            const lowerKey = key.toLowerCase();
            if (
              lowerKey.includes('cache') ||
              lowerKey.includes('age') ||
              lowerKey.includes('expires') ||
              lowerKey === 'x-cache'
            ) {
              cacheHeaders[key] = value as string;
            }
          });
        }

        const dataLower = (response.data || '').toLowerCase();
        const vulnerable = !!(
          dataLower.includes('evil.com') ||
          dataLower.includes('attacker.com') ||
          dataLower.includes('malicious') ||
          (response.headers &&
            Object.keys(response.headers).some((h) =>
              h.toLowerCase().includes(Object.keys(technique.headers)[0].toLowerCase())
            ))
        );

        let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
        let details = 'Header not reflected in response';

        if (vulnerable) {
          if (dataLower.includes('evil.com') || dataLower.includes('attacker.com')) {
            risk = 'Critical';
            details = 'Malicious header reflected in response content!';
          } else if (cacheHeaders['x-cache']?.toLowerCase().includes('hit')) {
            risk = 'High';
            details = 'Response is cacheable - poisoning may affect other users';
          } else {
            risk = 'Medium';
            details = 'Header processed but impact unclear';
          }
        }

        testResults.push({
          technique: technique.name,
          description: technique.desc,
          headers: technique.headers,
          statusCode: response.status || 0,
          cacheHeaders,
          vulnerable,
          risk,
          details,
        });
      } catch (error) {
        testResults.push({
          technique: technique.name,
          description: technique.desc,
          headers: technique.headers,
          statusCode: 0,
          cacheHeaders: {},
          vulnerable: false,
          risk: 'Low',
          details: `Error: ${error instanceof Error ? error.message : 'Unknown'}`,
        });
      }
    }

    setResults(testResults);
    setLoading(false);
  };

  const vulnerableCount = results.filter((r) => r.vulnerable).length;
  const criticalCount = results.filter((r) => r.risk === 'Critical').length;
  const highCount = results.filter((r) => r.risk === 'High').length;

  return (
    <ToolWrapper
      title="Cache Poisoning Scanner"
      icon={<ShieldIcon />}
      description="Test for web cache poisoning vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com"
            className={styles.input}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={testCachePoisoning}
            disabled={loading || !targetUrl}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Start Cache Poisoning Scan'
            )}
          </button>
        </div>
      </div>

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.grid3} style={{ marginBottom: '16px' }}>
            <div className={styles.statCard}>
              <div className={styles.statValue}>{results.length}</div>
              <div className={styles.statLabel}>Techniques Tested</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statValueError}>{vulnerableCount}</div>
              <div className={styles.statLabel}>Vulnerable</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statValue}>{criticalCount + highCount}</div>
              <div className={styles.statLabel}>Critical/High Risk</div>
            </div>
          </div>

          {results.map((result, idx) => (
            <div
              key={idx}
              className={styles.resultItem}
              style={{ borderLeft: result.vulnerable ? '3px solid #ff6b8a' : undefined }}
            >
              <div
                className={styles.flexRow}
                style={{ justifyContent: 'space-between', marginBottom: '8px' }}
              >
                <div>
                  <strong>{result.technique}</strong>
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
                    style={{ marginLeft: '8px' }}
                  >
                    {result.risk}
                  </span>
                  {result.vulnerable && (
                    <span style={{ color: '#ff6b8a', marginLeft: '8px', fontWeight: 600 }}>
                      VULNERABLE
                    </span>
                  )}
                </div>
                <span
                  className={result.statusCode === 200 ? styles.badgeSuccess : styles.badgeNeutral}
                >
                  {result.statusCode}
                </span>
              </div>
              <p
                style={{
                  color: 'var(--color-text-tertiary)',
                  fontSize: '13px',
                  marginBottom: '8px',
                }}
              >
                {result.description}
              </p>
              <p style={{ color: 'var(--color-text-secondary)', fontSize: '13px' }}>
                {result.details}
              </p>
              <div className={styles.codeBlock} style={{ marginTop: '8px', fontSize: '11px' }}>
                {Object.entries(result.headers).map(([key, value]) => (
                  <div key={key}>
                    <span style={{ color: 'var(--color-accent)' }}>{key}:</span> {value}
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
