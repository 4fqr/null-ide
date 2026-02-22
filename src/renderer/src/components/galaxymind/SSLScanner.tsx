import React, { useState } from 'react';
import { LockIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

interface SSLCheck {
  check: string;
  status: 'pass' | 'fail' | 'warning' | 'info';
  message: string;
  severity: 'Low' | 'Medium' | 'High' | 'Critical';
}

export const SSLScanner: React.FC = () => {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<SSLCheck[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState('');

  const scanSSL = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    try {
      setIsScanning(true);
      setError('');
      setResults([]);

      const targetUrl = url.startsWith('http') ? url : `https://${url}`;
      const response = await window.electronAPI.net.httpFetch(targetUrl, {
        method: 'GET',
        timeout: 10000,
      });

      const checks: SSLCheck[] = [];

      if (!response.success) {
        if (response.error?.includes('certificate') || response.error?.includes('SSL')) {
          checks.push({
            check: 'SSL/TLS Connection',
            status: 'fail',
            message: `SSL/TLS Error: ${response.error}`,
            severity: 'Critical',
          });
        } else {
          checks.push({
            check: 'Connection',
            status: 'fail',
            message: response.error || 'Connection failed',
            severity: 'High',
          });
        }
        setResults(checks);
        setIsScanning(false);
        return;
      }

      checks.push({
        check: 'SSL/TLS Connection',
        status: 'pass',
        message: 'Successfully established secure connection',
        severity: 'Low',
      });

      if (response.headers) {
        const strictTransportSecurity = response.headers['strict-transport-security'];
        if (strictTransportSecurity) {
          const maxAge = strictTransportSecurity.match(/max-age=(\d+)/)?.[1];
          const includesSubDomains = strictTransportSecurity.includes('includeSubDomains');
          const preload = strictTransportSecurity.includes('preload');

          if (maxAge && parseInt(maxAge) >= 31536000 && includesSubDomains) {
            checks.push({
              check: 'HSTS (Strict-Transport-Security)',
              status: 'pass',
              message: `Properly configured: max-age=${maxAge}${includesSubDomains ? ', includeSubDomains' : ''}${preload ? ', preload' : ''}`,
              severity: 'Low',
            });
          } else {
            checks.push({
              check: 'HSTS (Strict-Transport-Security)',
              status: 'warning',
              message: `Weak HSTS config: max-age=${maxAge}`,
              severity: 'Medium',
            });
          }
        } else {
          checks.push({
            check: 'HSTS (Strict-Transport-Security)',
            status: 'fail',
            message: 'HSTS header not present - vulnerable to SSL stripping attacks',
            severity: 'High',
          });
        }

        if (url.startsWith('https://') || targetUrl.startsWith('https://')) {
          checks.push({
            check: 'HTTPS Protocol',
            status: 'pass',
            message: 'Site uses HTTPS',
            severity: 'Low',
          });
        } else {
          checks.push({
            check: 'HTTPS Protocol',
            status: 'fail',
            message: 'Site does not enforce HTTPS',
            severity: 'Critical',
          });
        }

        const mixedContent = response.data?.match(/http:\/\/[^\s"']+/gi) || [];
        if (mixedContent.length > 0) {
          checks.push({
            check: 'Mixed Content',
            status: 'fail',
            message: `Found ${mixedContent.length} insecure HTTP resources loaded over HTTPS`,
            severity: 'High',
          });
        } else {
          checks.push({
            check: 'Mixed Content',
            status: 'pass',
            message: 'No insecure resources detected',
            severity: 'Low',
          });
        }

        const publicKeyPins = response.headers['public-key-pins'];
        if (publicKeyPins) {
          checks.push({
            check: 'Public Key Pinning (HPKP)',
            status: 'info',
            message: 'Certificate pinning detected (deprecated feature)',
            severity: 'Low',
          });
        }
      }

      checks.push({
        check: 'Certificate Validation',
        status: 'info',
        message: 'Certificate appears valid (detailed inspection requires system tools)',
        severity: 'Low',
      });

      setResults(checks);
    } catch (err) {
      setError(`Scan error: ${(err as Error).message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'pass':
        return '#00ff41';
      case 'fail':
        return '#ff0055';
      case 'warning':
        return '#ffaa00';
      case 'info':
        return '#00aaff';
      default:
        return '#ffffff';
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical':
        return '#ff0055';
      case 'High':
        return '#ff3366';
      case 'Medium':
        return '#ffaa00';
      case 'Low':
        return '#00ff41';
      default:
        return '#ffffff';
    }
  };

  return (
    <ToolWrapper
      title="SSL/TLS Scanner"
      icon={<LockIcon />}
      description="Analyze SSL/TLS configuration and security"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            onKeyPress={(e) => e.key === 'Enter' && scanSSL()}
            className={styles.input}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button onClick={scanSSL} disabled={isScanning} className={styles.primaryBtn}>
            {isScanning ? 'SCANNING...' : 'SCAN SSL/TLS'}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>
              Scan Results ({results.filter((r) => r.status === 'fail').length} issues found)
            </span>
          </div>

          {results.map((result, idx) => (
            <div
              key={idx}
              className={styles.resultItem}
              style={{ borderLeft: `3px solid ${getStatusColor(result.status)}` }}
            >
              <div className={styles.resultRow}>
                <span style={{ fontWeight: 'bold', color: getStatusColor(result.status) }}>
                  {result.check}
                </span>
                <span
                  style={{
                    padding: '2px 8px',
                    backgroundColor: getSeverityColor(result.severity),
                    color: '#000',
                    borderRadius: '3px',
                    fontSize: '12px',
                    fontWeight: 'bold',
                  }}
                >
                  {result.severity}
                </span>
              </div>
              <div style={{ color: '#aaa', fontSize: '14px', marginTop: '8px' }}>
                {result.message}
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};
export default SSLScanner;
