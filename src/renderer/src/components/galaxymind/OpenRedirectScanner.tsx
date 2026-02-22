import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { TargetIcon } from '../common/Icons';

interface RedirectTest {
  payload: string;
  vulnerable: boolean;
  finalUrl: string;
  status: number;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
}

export const OpenRedirectScanner: React.FC = () => {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<RedirectTest[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState('');

  const redirectPayloads = [
    '//evil.com',
    'https://evil.com',
    '//google.com',
    '/\\evil.com',
    '//evil%00.com',
    '@evil.com',
    'javascript:alert(1)',
    '%0d%0aLocation:https://evil.com',
    '\\\\evil.com',
    '////evil.com',
    'https:evil.com',
    '//evil.com/%2f..',
    '//www.google.com',
    '/redirect?url=https://evil.com',
  ];

  const scanRedirects = async () => {
    if (!url.trim()) {
      setError('Please enter a URL (e.g., https://example.com/redirect?url=)');
      return;
    }

    try {
      setIsScanning(true);
      setError('');
      setResults([]);

      const baseUrl = url.startsWith('http') ? url : `https://${url}`;
      const testResults: RedirectTest[] = [];

      for (const payload of redirectPayloads) {
        try {
          const testUrl = baseUrl.includes('?')
            ? `${baseUrl}${payload}`
            : `${baseUrl}?url=${payload}`;

          const response = await window.electronAPI.net.httpFetch(testUrl, {
            method: 'GET',
            timeout: 5000,
          });

          const isRedirect = !!(response.status && response.status >= 300 && response.status < 400);
          const locationHeader = response.headers?.location || response.headers?.Location;
          const vulnerable = !!(
            isRedirect &&
            locationHeader &&
            (locationHeader.includes('evil.com') ||
              locationHeader.includes('google.com') ||
              locationHeader.startsWith('//') ||
              locationHeader.startsWith('javascript:'))
          );

          let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
          if (vulnerable) {
            if (locationHeader?.includes('javascript:')) {
              risk = 'Critical';
            } else if (locationHeader?.includes('evil.com')) {
              risk = 'High';
            } else {
              risk = 'Medium';
            }
          }

          testResults.push({
            payload,
            vulnerable,
            finalUrl: locationHeader || 'No redirect',
            status: response.status || 0,
            risk,
          });
        } catch (err) {
          testResults.push({
            payload,
            vulnerable: false,
            finalUrl: `Error: ${(err as Error).message}`,
            status: 0,
            risk: 'Low',
          });
        }
      }

      setResults(testResults);
    } catch (err) {
      setError(`Scan error: ${(err as Error).message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const getRiskBadgeClass = (risk: string) => {
    switch (risk) {
      case 'Critical':
        return styles.badgeCritical;
      case 'High':
        return styles.badgeHigh;
      case 'Medium':
        return styles.badgeMedium;
      case 'Low':
        return styles.badgeLow;
      default:
        return styles.badgeNeutral;
    }
  };

  return (
    <ToolWrapper
      title="Open Redirect Scanner"
      icon={<TargetIcon />}
      description="Scan URLs for open redirect vulnerabilities"
    >
      <div className={styles.inputGroup}>
        <label className={styles.label}>Target URL</label>
        <input
          type="text"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com/redirect?url="
          onKeyPress={(e) => e.key === 'Enter' && scanRedirects()}
          className={styles.input}
        />
        <p style={{ fontSize: '12px', color: 'var(--color-text-tertiary)', marginTop: '8px' }}>
          Enter a URL with a redirect parameter (e.g., https://example.com/redirect?url=)
        </p>
      </div>

      <div className={styles.buttonGroup}>
        <button onClick={scanRedirects} disabled={isScanning} className={styles.primaryBtn}>
          {isScanning ? 'Scanning...' : 'Scan Redirects'}
        </button>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <span className={styles.resultTitle}>
            Redirect Tests ({results.filter((r) => r.vulnerable).length} vulnerabilities found)
          </span>

          {results
            .filter((r) => r.vulnerable)
            .map((result, idx) => (
              <div key={idx} className={styles.resultItem}>
                <div className={styles.resultRow}>
                  <span className={styles.textError}>VULNERABLE - {result.payload}</span>
                  <span className={`${styles.badge} ${getRiskBadgeClass(result.risk)}`}>
                    {result.risk}
                  </span>
                </div>
                <div
                  style={{
                    color: 'var(--color-text-secondary)',
                    fontSize: '14px',
                    marginTop: '5px',
                  }}
                >
                  Redirects to: {result.finalUrl}
                </div>
                <div
                  style={{
                    color: 'var(--color-text-tertiary)',
                    fontSize: '12px',
                    marginTop: '3px',
                  }}
                >
                  Status: {result.status}
                </div>
              </div>
            ))}

          {results.filter((r) => r.vulnerable).length === 0 && (
            <div className={styles.successBox}>No open redirect vulnerabilities detected</div>
          )}
        </div>
      )}
    </ToolWrapper>
  );
};

export default OpenRedirectScanner;
