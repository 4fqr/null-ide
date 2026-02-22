import React, { useState } from 'react';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { DatabaseIcon } from '../common/Icons';

interface NoSQLResult {
  payload: string;
  vulnerable: boolean;
  response: string;
  status: number;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
}

export const NoSQLInjectionTester: React.FC = () => {
  const [url, setUrl] = useState('');
  const [paramName, setParamName] = useState('username');
  const [results, setResults] = useState<NoSQLResult[]>([]);
  const [isTesting, setIsTesting] = useState(false);
  const [error, setError] = useState('');

  const noSQLPayloads = [
    '{"$ne": null}',
    '{"$ne": ""}',
    '{"$gt": ""}',
    '{"$regex": ".*"}',
    '{"$where": "1==1"}',
    '{"$or": [{"a":1}, {"a":2}]}',
    "admin' || '1'=='1",
    "' || 1==1//",
    "' || 1==1%00",
    '{"$nin": []}',
  ];

  const testNoSQL = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    try {
      setIsTesting(true);
      setError('');
      setResults([]);

      const targetUrl = url.startsWith('http') ? url : `https://${url}`;
      const testResults: NoSQLResult[] = [];

      for (const payload of noSQLPayloads) {
        try {
          const testUrl = targetUrl.includes('?')
            ? `${targetUrl}&${paramName}=${encodeURIComponent(payload)}`
            : `${targetUrl}?${paramName}=${encodeURIComponent(payload)}`;

          const response = await window.electronAPI.net.httpFetch(testUrl, {
            method: 'GET',
            timeout: 5000,
          });

          const dataLower = (response.data || '').toLowerCase();
          const vulnerable =
            (response.status === 200 &&
              (dataLower.includes('user') ||
                dataLower.includes('admin') ||
                dataLower.includes('true') ||
                dataLower.includes('success'))) ||
            (response.data?.length ?? 0) > 100;

          let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
          if (vulnerable) {
            if (dataLower.includes('admin') || dataLower.includes('password')) {
              risk = 'Critical';
            } else {
              risk = 'High';
            }
          }

          testResults.push({
            payload,
            vulnerable,
            response: (response.data || '').substring(0, 100),
            status: response.status || 0,
            risk,
          });
        } catch (err) {
          testResults.push({
            payload,
            vulnerable: false,
            response: `Error: ${(err as Error).message}`,
            status: 0,
            risk: 'Low',
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

  const getRiskColor = (risk: string) => {
    switch (risk) {
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
      title="NoSQL Injection Tester"
      icon={<DatabaseIcon />}
      description="Test endpoints for NoSQL injection vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://api.example.com/users"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Parameter Name</label>
          <input
            type="text"
            className={styles.input}
            placeholder="username"
            value={paramName}
            onChange={(e) => setParamName(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testNoSQL} disabled={isTesting}>
            {isTesting ? 'TESTING...' : 'TEST NOSQL INJECTION'}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <h3 className={styles.resultTitle}>
            Results ({results.filter((r) => r.vulnerable).length} vulnerabilities)
          </h3>

          {results
            .filter((r) => r.vulnerable)
            .map((result, idx) => (
              <div
                key={idx}
                className={styles.resultItem}
                style={{ borderLeft: `3px solid ${getRiskColor(result.risk)}` }}
              >
                <div className={styles.resultRow}>
                  <span className={styles.textError}>VULNERABLE</span>
                  <span
                    style={{
                      padding: '2px 8px',
                      backgroundColor: getRiskColor(result.risk),
                      color: '#000',
                      borderRadius: '3px',
                      fontSize: '12px',
                      fontWeight: 'bold',
                    }}
                  >
                    {result.risk}
                  </span>
                </div>
                <div className={styles.codeBlock}>{result.payload}</div>
                <div style={{ color: '#666', fontSize: '11px', marginTop: '5px' }}>
                  Status: {result.status} | Response: {result.response}...
                </div>
              </div>
            ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default NoSQLInjectionTester;
