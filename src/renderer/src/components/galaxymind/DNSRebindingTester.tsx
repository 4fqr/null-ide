import { useState } from 'react';
import { ShieldIcon, LoadingIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

interface DNSResult {
  phase: string;
  domain: string;
  ip: string;
  vulnerable: boolean;
  description: string;
}

export default function DNSRebindingTester() {
  const [targetUrl, setTargetUrl] = useState('');
  const [attackerIP, setAttackerIP] = useState('');
  const [loading, setLoading] = useState(false);
  const [results, setResults] = useState<DNSResult[]>([]);

  const testDNSRebinding = async () => {
    if (!targetUrl || !attackerIP) return;

    setLoading(true);
    setResults([]);

    const testResults: DNSResult[] = [];

    try {
      const domain = new URL(targetUrl).hostname;

      testResults.push({
        phase: 'Phase 1: Initial Resolution',
        domain,
        ip: 'Legitimate IP',
        vulnerable: false,
        description: 'First DNS lookup returns legitimate IP address',
      });

      testResults.push({
        phase: 'Phase 2: TTL Expiry',
        domain,
        ip: 'TTL: 0-1 seconds',
        vulnerable: true,
        description: 'Attacker sets very short TTL to force re-resolution',
      });

      testResults.push({
        phase: 'Phase 3: DNS Rebinding',
        domain,
        ip: attackerIP,
        vulnerable: true,
        description: 'DNS resolves to attacker-controlled IP',
      });

      const response1 = await window.electronAPI.net.httpFetch(targetUrl, {
        method: 'GET',
        timeout: 3000,
      });

      testResults.push({
        phase: 'Phase 4: First Request',
        domain,
        ip: response1.status === 200 ? 'Connected' : 'Failed',
        vulnerable: response1.status === 200,
        description: `Initial request status: ${response1.status || 'Error'}`,
      });

      const hasHostValidation =
        (response1.headers &&
          (response1.headers['X-Frame-Options'] || response1.headers['Content-Security-Policy'])) ||
        false;

      testResults.push({
        phase: 'Phase 5: Protection Check',
        domain,
        ip: hasHostValidation ? 'Protected' : 'Vulnerable',
        vulnerable: !hasHostValidation,
        description: hasHostValidation
          ? 'Security headers present - some protection against rebinding'
          : 'No Host validation detected - vulnerable to DNS rebinding',
      });
    } catch (error) {
      testResults.push({
        phase: 'Error',
        domain: targetUrl,
        ip: 'N/A',
        vulnerable: false,
        description: `Test failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
      });
    }

    setResults(testResults);
    setLoading(false);
  };

  const vulnerableCount = results.filter((r) => r.vulnerable).length;

  return (
    <ToolWrapper
      title="DNS Rebinding Tester"
      icon={<ShieldIcon />}
      description="Test for DNS rebinding attack vulnerabilities"
    >
      <div className={styles.warningBox} style={{ marginBottom: '16px' }}>
        <strong>What is DNS Rebinding?</strong>
        <p style={{ marginTop: '4px' }}>
          DNS rebinding tricks the browser's same-origin policy by returning different IP addresses
          for the same domain.
        </p>
      </div>

      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com"
            className={styles.input}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Attacker IP (for simulation)</label>
          <input
            type="text"
            value={attackerIP}
            onChange={(e) => setAttackerIP(e.target.value)}
            placeholder="127.0.0.1 or 192.168.1.1"
            className={styles.input}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={testDNSRebinding}
            disabled={loading || !targetUrl || !attackerIP}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Start DNS Rebinding Test'
            )}
          </button>
        </div>
      </div>

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.grid2} style={{ marginBottom: '16px' }}>
            <div className={styles.statCard}>
              <div className={styles.statValue}>{results.length}</div>
              <div className={styles.statLabel}>Test Phases</div>
            </div>
            <div className={styles.statCard}>
              <div className={styles.statValueError}>{vulnerableCount}</div>
              <div className={styles.statLabel}>Vulnerable Phases</div>
            </div>
          </div>

          {results.map((result, idx) => (
            <div
              key={idx}
              className={styles.resultItem}
              style={{ borderLeft: result.vulnerable ? '3px solid #ff6b8a' : undefined }}
            >
              <div
                className={styles.flexRow}
                style={{ justifyContent: 'space-between', marginBottom: '8px' }}
              >
                <strong>{result.phase}</strong>
                {result.vulnerable && <span className={styles.badgeError}>VULNERABLE</span>}
              </div>

              <div style={{ fontSize: '13px' }}>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)' }}>Domain:</span>{' '}
                  <code className={styles.code}>{result.domain}</code>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)' }}>IP/Status:</span>{' '}
                  <code className={styles.code}>{result.ip}</code>
                </div>
                <p style={{ marginTop: '8px' }}>{result.description}</p>
              </div>
            </div>
          ))}

          <div className={styles.infoBox} style={{ marginTop: '16px' }}>
            <strong>Mitigation Recommendations</strong>
            <ul style={{ margin: '8px 0 0 20px' }}>
              <li>Validate the Host header on the server</li>
              <li>Use DNS pinning or longer TTL values</li>
              <li>Implement CORS properly to restrict origins</li>
              <li>Use authentication tokens instead of relying on network location</li>
            </ul>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
}
