import React, { useState } from 'react';
import { ShieldIcon, LoadingIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

interface RaceResult {
  requestId: number;
  statusCode: number;
  responseTime: number;
  responseData: string;
}

interface RaceAnalysis {
  vulnerable: boolean;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  uniqueResponses: number;
  totalRequests: number;
  inconsistencies: string[];
}

const RaceConditionTester: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [requestCount, setRequestCount] = useState(10);
  const [method, setMethod] = useState<'GET' | 'POST'>('POST');
  const [postData, setPostData] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<RaceResult[]>([]);
  const [analysis, setAnalysis] = useState<RaceAnalysis | null>(null);

  const testRaceCondition = async () => {
    if (!targetUrl) return;

    setLoading(true);
    setResults([]);
    setAnalysis(null);

    const requests = Array.from({ length: requestCount }, (_, i) => sendRequest(i + 1));

    try {
      const responses = await Promise.all(requests);
      setResults(responses);
      analyzeResults(responses);
    } catch (error) {
      console.error('Race condition test failed:', error);
    }

    setLoading(false);
  };

  const sendRequest = async (requestId: number): Promise<RaceResult> => {
    const startTime = Date.now();
    try {
      const response = await window.electronAPI.net.httpFetch(targetUrl, {
        method,
        body: method === 'POST' ? postData : undefined,
        headers: method === 'POST' ? { 'Content-Type': 'application/json' } : {},
        timeout: 10000,
      });
      const responseTime = Date.now() - startTime;

      return {
        requestId,
        statusCode: response.status || 0,
        responseTime,
        responseData: response.data || '',
      };
    } catch (error) {
      return {
        requestId,
        statusCode: 0,
        responseTime: Date.now() - startTime,
        responseData: `Error: ${error instanceof Error ? error.message : 'Unknown'}`,
      };
    }
  };

  const analyzeResults = (responses: RaceResult[]) => {
    const uniqueResponses = new Set(responses.map((r) => `${r.statusCode}:${r.responseData}`)).size;
    const inconsistencies: string[] = [];

    const statusCodes = new Set(responses.map((r) => r.statusCode));
    if (statusCodes.size > 1) {
      inconsistencies.push(`Multiple status codes detected: ${Array.from(statusCodes).join(', ')}`);
    }

    const responseLengths = responses.map((r) => r.responseData.length);
    const minLength = Math.min(...responseLengths);
    const maxLength = Math.max(...responseLengths);
    if (maxLength - minLength > 10) {
      inconsistencies.push(`Response length variation: ${minLength}-${maxLength} characters`);
    }

    const avgTime = responses.reduce((sum, r) => sum + r.responseTime, 0) / responses.length;
    const timeVariations = responses.filter(
      (r) => Math.abs(r.responseTime - avgTime) > avgTime * 0.3
    );
    if (timeVariations.length > 0) {
      inconsistencies.push(`${timeVariations.length} requests had significant timing variations`);
    }

    const errors = responses.filter((r) => r.statusCode >= 400 || r.statusCode === 0);
    const successes = responses.filter((r) => r.statusCode >= 200 && r.statusCode < 300);
    if (errors.length > 0 && successes.length > 0) {
      inconsistencies.push(
        `Mixed success/error responses: ${successes.length} successes, ${errors.length} errors`
      );
    }

    const vulnerable = uniqueResponses > 1 || inconsistencies.length >= 2;
    let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';

    if (vulnerable) {
      if (inconsistencies.length >= 3 && statusCodes.size > 1) {
        risk = 'Critical';
      } else if (inconsistencies.length >= 2) {
        risk = 'High';
      } else {
        risk = 'Medium';
      }
    }

    setAnalysis({
      vulnerable,
      risk,
      uniqueResponses,
      totalRequests: responses.length,
      inconsistencies,
    });
  };

  const getRiskBadgeClass = (risk: string) => {
    switch (risk) {
      case 'Critical':
        return styles.badgeCritical;
      case 'High':
        return styles.badgeHigh;
      case 'Medium':
        return styles.badgeMedium;
      default:
        return styles.badgeLow;
    }
  };

  return (
    <ToolWrapper
      title="Race Condition Tester"
      icon={<ShieldIcon />}
      description="Test for race conditions with concurrent requests"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com/api/purchase"
            className={styles.input}
          />
        </div>

        <div className={styles.grid2}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Request Count</label>
            <input
              type="number"
              value={requestCount}
              onChange={(e) => setRequestCount(Math.max(2, parseInt(e.target.value) || 10))}
              min="2"
              max="50"
              className={styles.input}
            />
          </div>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Method</label>
            <select
              value={method}
              onChange={(e) => setMethod(e.target.value as 'GET' | 'POST')}
              className={styles.select}
            >
              <option value="GET">GET</option>
              <option value="POST">POST</option>
            </select>
          </div>
        </div>

        {method === 'POST' && (
          <div className={styles.inputGroup}>
            <label className={styles.label}>POST Data (JSON)</label>
            <textarea
              value={postData}
              onChange={(e) => setPostData(e.target.value)}
              placeholder='{"amount": 100, "product_id": 123}'
              className={styles.textarea}
              rows={3}
            />
          </div>
        )}

        <div className={styles.buttonGroup}>
          <button
            onClick={testRaceCondition}
            disabled={loading || !targetUrl}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Testing Race Condition...
              </>
            ) : (
              'Start Race Condition Test'
            )}
          </button>
        </div>
      </div>

      {analysis && (
        <div className={analysis.vulnerable ? styles.errorBox : styles.successBox}>
          <div className={styles.resultRow}>
            <h3 className={styles.resultTitle}>Analysis Results</h3>
            <span className={`${styles.badge} ${getRiskBadgeClass(analysis.risk)}`}>
              {analysis.risk}
            </span>
            {analysis.vulnerable && <span className={styles.textError}>VULNERABLE</span>}
          </div>

          <div className={styles.grid2}>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Total Requests</div>
              <div className={styles.statValue}>{analysis.totalRequests}</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Unique Responses</div>
              <div className={styles.statValue}>{analysis.uniqueResponses}</div>
            </div>
          </div>

          {analysis.inconsistencies.length > 0 && (
            <div className={styles.mt16}>
              <h4 className={styles.label}>Detected Inconsistencies:</h4>
              <ul style={{ margin: '8px 0 0 20px', padding: 0 }}>
                {analysis.inconsistencies.map((inc, idx) => (
                  <li key={idx} className={styles.textError}>
                    {inc}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {!analysis.vulnerable && (
            <p className={styles.textSuccess}>
              All responses were consistent. No race condition detected.
            </p>
          )}
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.tableWrapper}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Request #</th>
                  <th>Status</th>
                  <th>Time (ms)</th>
                  <th>Response Preview</th>
                </tr>
              </thead>
              <tbody>
                {results.map((result) => (
                  <tr key={result.requestId}>
                    <td>{result.requestId}</td>
                    <td>
                      <span
                        className={`${styles.badge} ${
                          result.statusCode >= 200 && result.statusCode < 300
                            ? styles.badgeSuccess
                            : result.statusCode === 0
                              ? styles.badgeNeutral
                              : styles.badgeError
                        }`}
                      >
                        {result.statusCode}
                      </span>
                    </td>
                    <td>{result.responseTime}</td>
                    <td className={styles.code}>
                      {result.responseData.substring(0, 100)}
                      {result.responseData.length > 100 ? '...' : ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default RaceConditionTester;
