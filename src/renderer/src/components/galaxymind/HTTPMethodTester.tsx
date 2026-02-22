import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { ZapIcon } from '../common/Icons';

interface MethodTest {
  method: string;
  allowed: boolean;
  status: number;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  description: string;
}

export const HTTPMethodTester: React.FC = () => {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<MethodTest[]>([]);
  const [isTesting, setIsTesting] = useState(false);
  const [error, setError] = useState('');

  const dangerousMethods = ['PUT', 'DELETE', 'TRACE', 'CONNECT', 'PATCH'];
  const allMethods = [
    'GET',
    'POST',
    'PUT',
    'DELETE',
    'HEAD',
    'OPTIONS',
    'TRACE',
    'CONNECT',
    'PATCH',
  ];

  const testMethods = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    try {
      setIsTesting(true);
      setError('');
      setResults([]);

      const targetUrl = url.startsWith('http') ? url : `https://${url}`;
      const methodTests: MethodTest[] = [];

      for (const method of allMethods) {
        try {
          const response = await window.electronAPI.net.httpFetch(targetUrl, {
            method: method as 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD',
            timeout: 5000,
          });

          if (response.success && response.status) {
            const allowed = response.status >= 200 && response.status < 400;
            const isDangerous = dangerousMethods.includes(method);

            let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
            let description = `${method} method returned ${response.status}`;

            if (allowed && isDangerous) {
              if (method === 'TRACE') {
                risk = 'Medium';
                description =
                  'TRACE method enabled - vulnerable to XST (Cross-Site Tracing) attacks';
              } else if (method === 'PUT' || method === 'DELETE') {
                risk = 'Critical';
                description = `${method} method allowed - arbitrary file ${method === 'PUT' ? 'upload' : 'deletion'} possible`;
              } else if (method === 'CONNECT') {
                risk = 'High';
                description = 'CONNECT method enabled - server can be used as proxy';
              } else if (method === 'PATCH') {
                risk = 'Medium';
                description = 'PATCH method enabled - verify proper authentication';
              }
            } else if (allowed) {
              description = `${method} method allowed (standard)`;
            } else {
              description = `${method} method not allowed (${response.status})`;
            }

            methodTests.push({
              method,
              allowed,
              status: response.status,
              risk,
              description,
            });
          } else {
            methodTests.push({
              method,
              allowed: false,
              status: response.status || 0,
              risk: 'Low',
              description: `${method} method returned error or timeout`,
            });
          }
        } catch (err) {
          methodTests.push({
            method,
            allowed: false,
            status: 0,
            risk: 'Low',
            description: `${method} test failed: ${(err as Error).message}`,
          });
        }
      }

      const optionsTest = methodTests.find((t) => t.method === 'OPTIONS');
      if (optionsTest && optionsTest.allowed) {
        methodTests.push({
          method: 'SECURITY NOTE',
          allowed: true,
          status: 200,
          risk: 'Low',
          description: 'OPTIONS method reveals allowed HTTP methods - consider restricting',
        });
      }

      setResults(methodTests);
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
        return styles.badgeLow;
      default:
        return styles.badgeNeutral;
    }
  };

  return (
    <ToolWrapper
      title="HTTP Method Tester"
      icon={<ZapIcon />}
      description="Test HTTP methods for security vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com/api/endpoint"
            onKeyPress={(e) => e.key === 'Enter' && testMethods()}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testMethods} disabled={isTesting}>
            {isTesting ? 'Testing...' : 'Test HTTP Methods'}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {isTesting && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing HTTP methods...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <div className={styles.resultTitle}>
              Method Test Results (
              {results.filter((r) => r.risk === 'Critical' || r.risk === 'High').length} critical
              issues)
            </div>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div className={styles.resultRow}>
                <span className={styles.resultLabel}>
                  {result.method} [{result.status || 'N/A'}]
                </span>
                <span className={`${styles.badge} ${getRiskBadgeClass(result.risk)}`}>
                  {result.risk}
                </span>
              </div>
              <div className={styles.resultContent}>{result.description}</div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default HTTPMethodTester;
