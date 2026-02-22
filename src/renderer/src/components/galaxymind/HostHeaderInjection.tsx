import React, { useState } from 'react';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ServerIcon, LoadingIcon } from '../common/Icons';

interface HostHeaderResult {
  payload: string;
  vulnerable: boolean;
  location: string;
  status: number;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
}

export const HostHeaderInjection: React.FC = () => {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<HostHeaderResult[]>([]);
  const [isTesting, setIsTesting] = useState(false);
  const [error, setError] = useState('');

  const hostPayloads = [
    'evil.com',
    'evil.com:80',
    'localhost',
    '127.0.0.1',
    'attacker.com',
    'evil.com%00.target.com',
    'target.com.evil.com',
    'target.com@evil.com',
    '127.0.0.1#.target.com',
  ];

  const testHostHeader = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    try {
      setIsTesting(true);
      setError('');
      setResults([]);

      const targetUrl = url.startsWith('http') ? url : `https://${url}`;
      const testResults: HostHeaderResult[] = [];

      for (const payload of hostPayloads) {
        try {
          const response = await window.electronAPI.net.httpFetch(targetUrl, {
            method: 'GET',
            headers: {
              Host: payload,
            },
            timeout: 5000,
          });

          const location = response.headers?.location || response.headers?.Location || '';
          const vulnerable =
            location.includes(payload) || response.data?.includes(payload) || false;

          let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
          let description = '';

          if (vulnerable) {
            if (location.includes(payload)) {
              risk = 'Critical';
              description = `Host header injection in Location header - redirects to ${payload}`;
            } else if (response.data?.includes(payload)) {
              risk = 'High';
              description = `Host header reflected in response body - potential cache poisoning`;
            }
          } else if (response.status === 400 || response.status === 421) {
            risk = 'Low';
            description = `Server properly rejects invalid Host header`;
          } else {
            risk = 'Low';
            description = `Host header not reflected`;
          }

          testResults.push({
            payload,
            vulnerable,
            location,
            status: response.status || 0,
            risk,
            description,
          });
        } catch (err) {
          testResults.push({
            payload,
            vulnerable: false,
            location: '',
            status: 0,
            risk: 'Low',
            description: `Test failed: ${(err as Error).message}`,
          });
        }
      }

      setResults(testResults);
    } catch (err) {
      setError(`Test error: ${(err as Error).message}`);
    } finally {
      setIsTesting(false);
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
      default:
        return styles.badgeLow;
    }
  };

  return (
    <ToolWrapper
      title="Host Header Injection Tester"
      icon={<ServerIcon />}
      description="Test for Host header injection vulnerabilities that can lead to cache poisoning and SSRF"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            onKeyPress={(e) => e.key === 'Enter' && testHostHeader()}
            className={styles.input}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button onClick={testHostHeader} disabled={isTesting} className={styles.primaryBtn}>
            {isTesting ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test Host Header'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {isTesting && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing host header injection...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>
              Results ({results.filter((r) => r.vulnerable).length} vulnerabilities found)
            </span>
          </div>
          {results.map((result, idx) => (
            <div
              key={idx}
              className={`${styles.resultItem} ${result.vulnerable ? styles.rowError : ''}`}
            >
              <div className={styles.resultRow}>
                <span className={styles.resultLabel}>Host: {result.payload}</span>
                <span className={`${styles.badge} ${getRiskBadgeClass(result.risk)}`}>
                  {result.risk}
                </span>
              </div>
              <div
                style={{ color: 'var(--color-text-secondary)', fontSize: '13px', marginTop: '8px' }}
              >
                {result.description}
              </div>
              {result.location && (
                <div className={styles.textError} style={{ fontSize: '12px', marginTop: '5px' }}>
                  Location: {result.location}
                </div>
              )}
              <div
                style={{ color: 'var(--color-text-tertiary)', fontSize: '11px', marginTop: '3px' }}
              >
                Status: {result.status}
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default HostHeaderInjection;
