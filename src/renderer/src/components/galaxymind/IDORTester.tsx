import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { DatabaseIcon, CopyIcon } from '../common/Icons';

interface IDORResult {
  id: string;
  status: number;
  vulnerable: boolean;
  response: string;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  message: string;
}

export const IDORTester: React.FC = () => {
  const [baseUrl, setBaseUrl] = useState('');
  const [startId, setStartId] = useState('1');
  const [endId, setEndId] = useState('10');
  const [results, setResults] = useState<IDORResult[]>([]);
  const [isTesting, setIsTesting] = useState(false);
  const [error, setError] = useState('');

  const testIDOR = async () => {
    if (!baseUrl.trim()) {
      setError('Please enter a base URL (e.g., https://api.example.com/users/{ID})');
      return;
    }

    if (!baseUrl.includes('{ID}') && !baseUrl.includes('{id}')) {
      setError('URL must contain {ID} or {id} placeholder');
      return;
    }

    try {
      setIsTesting(true);
      setError('');
      setResults([]);

      const start = parseInt(startId);
      const end = parseInt(endId);

      if (isNaN(start) || isNaN(end) || start > end) {
        setError('Invalid ID range');
        setIsTesting(false);
        return;
      }

      const testResults: IDORResult[] = [];
      const responses: Map<number, { size: number; data: string }> = new Map();

      for (let id = start; id <= end; id++) {
        const testUrl = baseUrl.replace(/{ID}|{id}/g, id.toString());

        try {
          const response = await window.electronAPI.net.httpFetch(testUrl, {
            method: 'GET',
            timeout: 5000,
          });

          const dataSize = response.data?.length || 0;
          responses.set(id, { size: dataSize, data: response.data || '' });

          const status = response.status || 0;
          const vulnerable = status === 200 || status === 201;

          let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
          let message = '';

          if (vulnerable) {
            if (dataSize > 100) {
              risk = 'Critical';
              message = `IDOR vulnerability - unauthorized access to resource ${id}`;
            } else {
              risk = 'High';
              message = `Possible IDOR - resource ${id} accessible`;
            }
          } else if (status === 401 || status === 403) {
            risk = 'Low';
            message = `Access denied (proper authorization)`;
          } else if (status === 404) {
            risk = 'Low';
            message = `Resource not found`;
          } else {
            risk = 'Medium';
            message = `Unexpected status: ${status}`;
          }

          testResults.push({
            id: id.toString(),
            status,
            vulnerable,
            response: response.data?.substring(0, 100) || '',
            risk,
            message,
          });
        } catch (err) {
          testResults.push({
            id: id.toString(),
            status: 0,
            vulnerable: false,
            response: '',
            risk: 'Low',
            message: `Request failed: ${(err as Error).message}`,
          });
        }
      }

      const vulnerableResults = testResults.filter((r) => r.vulnerable);
      if (vulnerableResults.length > 1) {
        const sizes = vulnerableResults.map((r) => responses.get(parseInt(r.id))?.size || 0);
        const allSimilar = sizes.every((s) => Math.abs(s - sizes[0]) < 50);

        if (!allSimilar) {
          testResults.push({
            id: 'ANALYSIS',
            status: 200,
            vulnerable: true,
            response: '',
            risk: 'Critical',
            message: `IDOR CONFIRMED: ${vulnerableResults.length} resources accessible with varying content`,
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
        return styles.badgeLow;
      default:
        return styles.badgeNeutral;
    }
  };

  return (
    <ToolWrapper
      title="IDOR Tester"
      icon={<DatabaseIcon />}
      description="Test for Insecure Direct Object Reference vulnerabilities by iterating through resource IDs"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Base URL (use {'{ID}'} as placeholder)</label>
          <input
            type="text"
            className={styles.input}
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="https://api.example.com/users/{ID}"
          />
        </div>

        <div className={styles.flexRow}>
          <div className={styles.flex1}>
            <div className={styles.inputGroup}>
              <label className={styles.label}>Start ID</label>
              <input
                type="number"
                className={styles.input}
                value={startId}
                onChange={(e) => setStartId(e.target.value)}
              />
            </div>
          </div>
          <div className={styles.flex1}>
            <div className={styles.inputGroup}>
              <label className={styles.label}>End ID</label>
              <input
                type="number"
                className={styles.input}
                value={endId}
                onChange={(e) => setEndId(e.target.value)}
              />
            </div>
          </div>
        </div>

        <div className={styles.buttonGroup}>
          <button onClick={testIDOR} disabled={isTesting} className={styles.primaryBtn}>
            {isTesting ? (
              <>
                <span className={styles.spinner} />
                Testing...
              </>
            ) : (
              'Test IDOR'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>
              Results ({results.filter((r) => r.vulnerable).length} vulnerable)
            </span>
          </div>
          <div className={styles.resultContent}>
            {results.map((result, idx) => (
              <div key={idx} className={styles.resultItem}>
                <div className={styles.resultRow}>
                  <span className={styles.resultLabel}>
                    ID: {result.id} - Status: {result.status}
                  </span>
                  <span className={`${styles.badge} ${getRiskBadgeClass(result.risk)}`}>
                    {result.risk}
                  </span>
                </div>
                <div
                  style={{
                    color: 'var(--color-text-secondary)',
                    fontSize: '13px',
                    marginTop: '8px',
                  }}
                >
                  {result.message}
                </div>
                {result.response && (
                  <div className={styles.codeBlock} style={{ marginTop: '8px' }}>
                    {result.response}...
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default IDORTester;
