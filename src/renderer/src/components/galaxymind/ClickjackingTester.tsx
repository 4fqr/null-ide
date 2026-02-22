import { useState } from 'react';
import { ShieldIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

interface ClickjackTest {
  header: string;
  present: boolean;
  value: string;
  secure: boolean;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  recommendation: string;
}

export default function ClickjackingTester() {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<ClickjackTest[]>([]);
  const [isTesting, setIsTesting] = useState(false);
  const [error, setError] = useState('');
  const [htmlPreview, setHtmlPreview] = useState('');

  const testClickjacking = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    try {
      setIsTesting(true);
      setError('');
      setResults([]);

      const targetUrl = url.startsWith('http') ? url : `https://${url}`;
      const response = await window.electronAPI.net.httpFetch(targetUrl, {
        method: 'GET',
        timeout: 10000,
      });

      const tests: ClickjackTest[] = [];

      const xFrameOptions = response.headers?.['x-frame-options'];
      if (xFrameOptions) {
        const value = xFrameOptions.toLowerCase();
        const secure = value === 'deny' || value === 'sameorigin';
        tests.push({
          header: 'X-Frame-Options',
          present: true,
          value: xFrameOptions,
          secure,
          risk: secure ? 'Low' : 'Medium',
          recommendation: secure
            ? 'X-Frame-Options is properly configured'
            : 'X-Frame-Options should be set to DENY or SAMEORIGIN',
        });
      } else {
        tests.push({
          header: 'X-Frame-Options',
          present: false,
          value: 'Not set',
          secure: false,
          risk: 'High',
          recommendation: 'Add X-Frame-Options: DENY or SAMEORIGIN header',
        });
      }

      const csp = response.headers?.['content-security-policy'];
      if (csp) {
        const hasFrameAncestors = csp.includes('frame-ancestors');
        const frameAncestorsValue = csp.match(/frame-ancestors\s+([^;]+)/)?.[1] || '';
        const secure = frameAncestorsValue === "'none'" || frameAncestorsValue === "'self'";

        tests.push({
          header: 'CSP frame-ancestors',
          present: hasFrameAncestors,
          value: hasFrameAncestors ? frameAncestorsValue : 'Not set',
          secure,
          risk: hasFrameAncestors && secure ? 'Low' : hasFrameAncestors ? 'Medium' : 'High',
          recommendation: secure
            ? 'frame-ancestors directive is properly configured'
            : hasFrameAncestors
              ? "frame-ancestors should be set to 'none' or 'self'"
              : "Add frame-ancestors 'none' to Content-Security-Policy",
        });
      } else {
        tests.push({
          header: 'CSP frame-ancestors',
          present: false,
          value: 'Not set',
          secure: false,
          risk: 'High',
          recommendation: "Add Content-Security-Policy with frame-ancestors 'none'",
        });
      }

      const vulnerableToClickjacking = !xFrameOptions && (!csp || !csp.includes('frame-ancestors'));
      if (vulnerableToClickjacking) {
        tests.push({
          header: 'OVERALL ASSESSMENT',
          present: false,
          value: 'Vulnerable',
          secure: false,
          risk: 'Critical',
          recommendation:
            'Site is VULNERABLE to clickjacking attacks - add frame protection headers',
        });

        const poc = `<!DOCTYPE html>
<html>
<head>
  <title>Clickjacking PoC</title>
  <style>
    iframe { width: 800px; height: 600px; opacity: 0.1; position: absolute; top: 0; left: 0; z-index: 2; }
    .decoy { position: absolute; top: 100px; left: 100px; z-index: 1; }
  </style>
</head>
<body>
  <h1>Clickjacking Proof of Concept</h1>
  <div class="decoy">
    <h2>Click the button below:</h2>
    <button style="padding: 20px; font-size: 18px;">Win $1000!</button>
  </div>
  <iframe src="${targetUrl}"></iframe>
</body>
</html>`;
        setHtmlPreview(poc);
      } else {
        tests.push({
          header: 'OVERALL ASSESSMENT',
          present: true,
          value: 'Protected',
          secure: true,
          risk: 'Low',
          recommendation: 'Site appears protected against clickjacking attacks',
        });
      }

      setResults(tests);
    } catch (err) {
      setError(`Test error: ${(err as Error).message}`);
    } finally {
      setIsTesting(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <ToolWrapper
      title="Clickjacking Tester"
      icon={<ShieldIcon />}
      description="Test websites for clickjacking vulnerabilities"
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
          <button onClick={testClickjacking} disabled={isTesting} className={styles.primaryBtn}>
            {isTesting ? 'TESTING...' : 'TEST CLICKJACKING'}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Test Results</span>
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
                style={{ justifyContent: 'space-between', marginBottom: '5px' }}
              >
                <span style={{ fontWeight: 'bold' }}>{result.header}</span>
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
              <div
                style={{ color: 'var(--color-text-tertiary)', fontSize: '14px', marginTop: '5px' }}
              >
                Value: {result.value}
              </div>
              <div
                style={{ color: 'var(--color-text-secondary)', fontSize: '13px', marginTop: '5px' }}
              >
                {result.recommendation}
              </div>
            </div>
          ))}

          {htmlPreview && (
            <div style={{ marginTop: '20px' }}>
              <div
                className={styles.resultTitle}
                style={{ color: '#ff6b8a', marginBottom: '10px' }}
              >
                Proof of Concept (Save as .html)
              </div>
              <div style={{ position: 'relative' }}>
                <pre className={styles.codeBlock} style={{ maxHeight: '300px' }}>
                  {htmlPreview}
                </pre>
                <button onClick={() => copyToClipboard(htmlPreview)} className={styles.copyBtn}>
                  COPY
                </button>
              </div>
            </div>
          )}
        </div>
      )}
    </ToolWrapper>
  );
}
