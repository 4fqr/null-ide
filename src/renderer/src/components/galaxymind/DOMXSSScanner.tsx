import { useState } from 'react';
import { ShieldIcon, LoadingIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

interface DOMXSSResult {
  source: string;
  sink: string;
  payload: string;
  vulnerable: boolean;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
}

export default function DOMXSSScanner() {
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<DOMXSSResult[]>([]);
  const [pageSource, setPageSource] = useState('');

  const domXSSTests = [
    {
      source: 'location.hash',
      payload: '#<img src=x onerror=alert(1)>',
      sink: 'innerHTML',
      desc: 'Hash parameter to innerHTML injection',
    },
    {
      source: 'location.search',
      payload: '?q=<script>alert(1)</script>',
      sink: 'document.write',
      desc: 'Query parameter to document.write',
    },
    {
      source: 'document.URL',
      payload: 'javascript:alert(1)',
      sink: 'eval',
      desc: 'URL to eval() execution',
    },
    {
      source: 'location.hash',
      payload: '#javascript:alert(1)',
      sink: 'location.href',
      desc: 'Hash to location.href assignment',
    },
    {
      source: 'document.referrer',
      payload: '<img src=x onerror=alert(1)>',
      sink: 'innerHTML',
      desc: 'Referrer to innerHTML injection',
    },
    {
      source: 'window.name',
      payload: '<svg/onload=alert(1)>',
      sink: 'document.body.innerHTML',
      desc: 'window.name to body innerHTML',
    },
  ];

  const testDOMXSS = async () => {
    if (!targetUrl) return;

    setLoading(true);
    setResults([]);
    setPageSource('');

    const testResults: DOMXSSResult[] = [];

    try {
      const baseResponse = await window.electronAPI.net.httpFetch(targetUrl, {
        method: 'GET',
        timeout: 5000,
      });
      const source = baseResponse.data || '';
      setPageSource(source);

      for (const test of domXSSTests) {
        const vulnerable = analyzeForDOMXSS(source, test.source, test.sink);
        let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';

        if (vulnerable) {
          if (test.sink === 'eval' || test.sink === 'document.write') {
            risk = 'Critical';
          } else if (test.sink === 'innerHTML' || test.sink === 'location.href') {
            risk = 'High';
          } else {
            risk = 'Medium';
          }
        }

        testResults.push({
          source: test.source,
          sink: test.sink,
          payload: test.payload,
          vulnerable,
          risk,
          description: test.desc,
        });
      }
    } catch (error) {
      console.error('DOM XSS scan error:', error);
    }

    setResults(testResults);
    setLoading(false);
  };

  const analyzeForDOMXSS = (source: string, domSource: string, sink: string): boolean => {
    const sourceLower = source.toLowerCase();

    const patterns = [
      domSource.includes('location.hash') && sourceLower.includes('location.hash'),
      domSource.includes('location.search') && sourceLower.includes('location.search'),
      domSource.includes('document.URL') && sourceLower.includes('document.url'),
      domSource.includes('document.referrer') && sourceLower.includes('document.referrer'),
      domSource.includes('window.name') && sourceLower.includes('window.name'),
      sink === 'innerHTML' && sourceLower.includes('.innerhtml'),
      sink === 'eval' && /eval\s*\(/.test(sourceLower),
      sink === 'document.write' && sourceLower.includes('document.write'),
      sink === 'location.href' && sourceLower.includes('location.href'),
    ];

    const hasSource = patterns.slice(0, 5).some((p) => p);
    const hasSink = patterns.slice(5).some((p) => p);

    return hasSource && hasSink;
  };

  const vulnerableCount = results.filter((r) => r.vulnerable).length;
  const criticalCount = results.filter((r) => r.risk === 'Critical').length;
  const highCount = results.filter((r) => r.risk === 'High').length;

  return (
    <ToolWrapper
      title="DOM XSS Scanner"
      icon={<ShieldIcon />}
      description="Analyze JavaScript code for DOM-based XSS vulnerabilities"
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
            onClick={testDOMXSS}
            disabled={loading || !targetUrl}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Start DOM XSS Scan'
            )}
          </button>
        </div>
      </div>

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.grid3} style={{ marginBottom: '16px' }}>
            <div className={styles.statCard}>
              <div className={styles.statValue}>{results.length}</div>
              <div className={styles.statLabel}>Patterns Tested</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statValueError}>{vulnerableCount}</div>
              <div className={styles.statLabel}>Vulnerable</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statValue}>{criticalCount + highCount}</div>
              <div className={styles.statLabel}>Critical/High</div>
            </div>
          </div>

          {results.map((result, idx) => (
            <div
              key={idx}
              className={styles.resultItem}
              style={{ borderLeft: result.vulnerable ? '3px solid #ff6b8a' : undefined }}
            >
              <div className={styles.flexRow} style={{ gap: '8px', marginBottom: '8px' }}>
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
                {result.vulnerable && <span className={styles.textError}>VULNERABLE</span>}
              </div>

              <p style={{ fontWeight: 600, marginBottom: '8px' }}>{result.description}</p>

              <div className={styles.codeBlock} style={{ fontSize: '12px' }}>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)' }}>Source:</span>{' '}
                  <span className={styles.textSuccess}>{result.source}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)' }}>Sink:</span>{' '}
                  <span style={{ color: '#ffaa00' }}>{result.sink}</span>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)' }}>Payload:</span>{' '}
                  <span className={styles.textError}>{result.payload}</span>
                </div>
              </div>
            </div>
          ))}

          {pageSource && (
            <div className={styles.resultItem} style={{ marginTop: '16px' }}>
              <strong>Page Source Analysis</strong>
              <pre
                className={styles.codeBlock}
                style={{ maxHeight: '200px', overflow: 'auto', marginTop: '8px' }}
              >
                {pageSource.substring(0, 2000)}
                {pageSource.length > 2000 ? '\n... (truncated)' : ''}
              </pre>
            </div>
          )}
        </div>
      )}
    </ToolWrapper>
  );
}
