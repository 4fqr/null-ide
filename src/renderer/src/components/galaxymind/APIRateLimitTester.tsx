import { useState } from 'react';
import { ShieldIcon, LoadingIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

interface RateLimitResult {
  requestId: number;
  statusCode: number;
  responseTime: number;
  blocked: boolean;
  timestamp: number;
}

interface RateLimitAnalysis {
  totalRequests: number;
  successfulRequests: number;
  blockedRequests: number;
  avgResponseTime: number;
  rateLimitDetected: boolean;
  rateLimitType?: string;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  details: string;
}

export default function APIRateLimitTester() {
  const [targetUrl, setTargetUrl] = useState('');
  const [requestCount, setRequestCount] = useState(20);
  const [requestDelay, setRequestDelay] = useState(100);
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<RateLimitResult[]>([]);
  const [analysis, setAnalysis] = useState<RateLimitAnalysis | null>(null);

  const testRateLimit = async () => {
    if (!targetUrl) return;

    setLoading(true);
    setResults([]);
    setAnalysis(null);

    const testResults: RateLimitResult[] = [];

    for (let i = 0; i < requestCount; i++) {
      const startTime = Date.now();
      try {
        const response = await window.electronAPI.net.httpFetch(targetUrl, {
          method: 'GET',
          timeout: 5000,
        });

        const blocked =
          response.status === 429 ||
          response.status === 403 ||
          response.status === 503 ||
          (response.data || '').toLowerCase().includes('rate limit');

        testResults.push({
          requestId: i + 1,
          statusCode: response.status || 0,
          responseTime: Date.now() - startTime,
          blocked,
          timestamp: Date.now(),
        });
      } catch {
        testResults.push({
          requestId: i + 1,
          statusCode: 0,
          responseTime: Date.now() - startTime,
          blocked: true,
          timestamp: Date.now(),
        });
      }

      setResults([...testResults]);

      if (i < requestCount - 1) {
        await new Promise((resolve) => setTimeout(resolve, requestDelay));
      }
    }

    analyzeRateLimit(testResults);
    setLoading(false);
  };

  const analyzeRateLimit = (responses: RateLimitResult[]) => {
    const totalRequests = responses.length;
    const successfulRequests = responses.filter((r) => r.statusCode === 200).length;
    const blockedRequests = responses.filter((r) => r.blocked).length;
    const avgResponseTime = responses.reduce((sum, r) => sum + r.responseTime, 0) / totalRequests;

    const rateLimitDetected = blockedRequests > 0;
    let rateLimitType = 'None detected';
    let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
    let details = 'No rate limiting detected - API may be vulnerable to abuse';

    if (rateLimitDetected) {
      const firstBlockedIndex = responses.findIndex((r) => r.blocked);
      rateLimitType = `Rate limit triggered after ${firstBlockedIndex + 1} requests`;

      if (blockedRequests === totalRequests) {
        risk = 'Low';
        details = 'All requests blocked - strong rate limiting in place';
      } else if (firstBlockedIndex > totalRequests * 0.8) {
        risk = 'Medium';
        details = 'Rate limit is lenient - may allow some abuse';
      } else if (firstBlockedIndex > totalRequests * 0.5) {
        risk = 'Low';
        details = 'Moderate rate limiting - good protection';
      } else {
        risk = 'Low';
        details = 'Strict rate limiting - strong protection';
      }
    } else {
      risk = 'Critical';
      details = 'NO RATE LIMITING DETECTED - API is vulnerable to abuse, DDoS, brute force attacks';
    }

    setAnalysis({
      totalRequests,
      successfulRequests,
      blockedRequests,
      avgResponseTime: Math.round(avgResponseTime),
      rateLimitDetected,
      rateLimitType,
      risk,
      details,
    });
  };

  return (
    <ToolWrapper
      title="API Rate Limit Tester"
      icon={<ShieldIcon />}
      description="Test API endpoints for rate limiting protection"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>API Endpoint</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://api.example.com/endpoint"
            className={styles.input}
          />
        </div>

        <div className={styles.grid2}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Request Count</label>
            <input
              type="number"
              value={requestCount}
              onChange={(e) => setRequestCount(Math.max(1, parseInt(e.target.value) || 20))}
              min="1"
              max="100"
              className={styles.input}
            />
          </div>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Delay (ms)</label>
            <input
              type="number"
              value={requestDelay}
              onChange={(e) => setRequestDelay(Math.max(0, parseInt(e.target.value) || 100))}
              min="0"
              max="5000"
              className={styles.input}
            />
          </div>
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={testRateLimit}
            disabled={loading || !targetUrl}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Testing ({results.length}/{requestCount})
              </>
            ) : (
              'Start Rate Limit Test'
            )}
          </button>
        </div>
      </div>

      {analysis && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Analysis Results</span>
            <span
              className={
                analysis.risk === 'Critical'
                  ? styles.badgeCritical
                  : analysis.risk === 'High'
                    ? styles.badgeHigh
                    : analysis.risk === 'Medium'
                      ? styles.badgeMedium
                      : styles.badgeLow
              }
            >
              {analysis.risk}
            </span>
          </div>
          <div className={styles.grid4}>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Total Requests</div>
              <div className={styles.statValue}>{analysis.totalRequests}</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Successful</div>
              <div className={styles.statValueSuccess}>{analysis.successfulRequests}</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Blocked</div>
              <div className={styles.statValueError}>{analysis.blockedRequests}</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Avg Time</div>
              <div className={styles.statValue}>{analysis.avgResponseTime}ms</div>
            </div>
          </div>
          <div className={styles.resultContent}>
            <p>
              <strong>Rate Limit Status:</strong>{' '}
              <span className={analysis.rateLimitDetected ? styles.textSuccess : styles.textError}>
                {analysis.rateLimitDetected ? 'DETECTED' : 'NOT DETECTED'}
              </span>
            </p>
            {analysis.rateLimitType && (
              <p>
                <strong>Details:</strong> {analysis.rateLimitType}
              </p>
            )}
            <p>{analysis.details}</p>
          </div>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Request Log</span>
          </div>
          <div className={styles.tableWrapper}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Request #</th>
                  <th>Status</th>
                  <th>Time (ms)</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {results.map((result) => (
                  <tr key={result.requestId} className={result.blocked ? styles.rowError : ''}>
                    <td>{result.requestId}</td>
                    <td>
                      <span
                        className={
                          result.statusCode === 200
                            ? styles.badgeSuccess
                            : result.statusCode === 429
                              ? styles.badgeError
                              : result.statusCode === 0
                                ? styles.badgeNeutral
                                : styles.badgeWarning
                        }
                      >
                        {result.statusCode}
                      </span>
                    </td>
                    <td>{result.responseTime}</td>
                    <td className={result.blocked ? styles.textError : styles.textSuccess}>
                      {result.blocked ? 'BLOCKED' : 'Success'}
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
}
