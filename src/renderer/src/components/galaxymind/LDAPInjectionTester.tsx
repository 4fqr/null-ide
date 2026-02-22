import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

interface LDAPResult {
  payload: string;
  statusCode: number;
  responseTime: number;
  vulnerable: boolean;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  evidence?: string;
}

const LDAPInjectionTester: React.FC = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<LDAPResult[]>([]);

  const ldapPayloads = [
    '*',
    '*)(uid=*))(|(uid=*',
    'admin)(&(password=*))',
    '*)(objectClass=*',
    '*)|(cn=*',
    '*))(|(password=*',
    '*))%00',
    '*()|%26',
    '*))(|(mail=*',
    '*)(uid=*)(|(uid=*',
    'admin*',
    '*((|userPassword=*',
    '*((|(uniqueMember=*',
    '*)(objectCategory=person',
    '*)(&(objectClass=user',
  ];

  const testLDAP = async () => {
    if (!targetUrl) return;

    setLoading(true);
    setResults([]);

    const testResults: LDAPResult[] = [];

    for (const payload of ldapPayloads) {
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
          (dataLower.includes('cn=') ||
            dataLower.includes('uid=') ||
            dataLower.includes('dn:') ||
            dataLower.includes('objectclass') ||
            dataLower.includes('ldap') ||
            dataLower.includes('distinguished name') ||
            dataStr.length > 500);

        let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
        let evidence = '';

        if (vulnerable) {
          if (
            dataLower.includes('cn=admin') ||
            dataLower.includes('userpassword') ||
            dataLower.includes('uid=0')
          ) {
            risk = 'Critical';
            evidence = 'Possible admin/sensitive data exposure';
          } else if (dataLower.includes('cn=') || dataLower.includes('uid=')) {
            risk = 'High';
            evidence = 'LDAP query data exposed';
          } else if (dataStr.length > 1000) {
            risk = 'High';
            evidence = 'Large response indicating data exposure';
          } else {
            risk = 'Medium';
            evidence = 'LDAP injection possible';
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
      title="LDAP Injection Tester"
      icon={<ShieldIcon />}
      description="Test for LDAP injection vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com/login"
            className={styles.input}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button onClick={testLDAP} disabled={loading || !targetUrl} className={styles.primaryBtn}>
            {loading ? (
              <>
                <LoadingIcon />
                Testing LDAP Injection...
              </>
            ) : (
              'Start LDAP Injection Test'
            )}
          </button>
        </div>
      </div>

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing payloads...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div
            className={styles.grid3}
            style={{ display: 'grid', gap: '16px', marginBottom: '20px' }}
          >
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

          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Test Results</span>
          </div>
          <div className={styles.tableWrapper}>
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
                        className={`${styles.badge} ${
                          result.statusCode === 200
                            ? styles.badgeSuccess
                            : result.statusCode === 0
                              ? styles.badgeNeutral
                              : styles.badgeWarning
                        }`}
                      >
                        {result.statusCode}
                      </span>
                    </td>
                    <td>{result.responseTime}</td>
                    <td>
                      <span className={result.vulnerable ? styles.textError : styles.textSuccess}>
                        {result.vulnerable ? 'YES' : 'NO'}
                      </span>
                    </td>
                    <td>
                      <span
                        className={`${styles.badge} ${
                          result.risk === 'Critical'
                            ? styles.badgeCritical
                            : result.risk === 'High'
                              ? styles.badgeHigh
                              : result.risk === 'Medium'
                                ? styles.badgeMedium
                                : styles.badgeLow
                        }`}
                      >
                        {result.risk}
                      </span>
                    </td>
                    <td>{result.evidence}</td>
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

export default LDAPInjectionTester;
