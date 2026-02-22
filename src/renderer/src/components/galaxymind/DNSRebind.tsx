import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { NetworkIcon, LoadingIcon } from '../common/Icons';

interface RebindingTest {
  vulnerable: boolean;
  timingAnalysis: {
    firstRequest: number;
    secondRequest: number;
    rebindTime: number;
  };
  details: string[];
  mitigation: string[];
}

export default function DNSRebind() {
  const { addToolResult } = useStore();
  const [domain, setDomain] = useState('');
  const [targetIP, setTargetIP] = useState('127.0.0.1');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<RebindingTest | null>(null);

  const testRebinding = async () => {
    if (!domain) return;

    setLoading(true);
    setResult(null);

    try {
      const details: string[] = [];
      const mitigation: string[] = [];
      let vulnerable = false;

      details.push(`Testing DNS rebinding attack on: ${domain}`);
      details.push(`Target IP: ${targetIP}`);

      const startTime1 = Date.now();
      try {
        const lookup1 = await window.electronAPI.net.dnsLookup(domain);
        const endTime1 = Date.now();
        const time1 = endTime1 - startTime1;

        const addresses1Arr = lookup1.addresses || [];
        details.push(`\nFirst DNS lookup:`);
        details.push(`  Resolved to: ${addresses1Arr.join(', ')}`);
        details.push(`  Time: ${time1}ms`);
        details.push(`  TTL: ${lookup1.ttl || 'N/A'}`);

        await new Promise((resolve) => setTimeout(resolve, 2000));

        const startTime2 = Date.now();
        const lookup2 = await window.electronAPI.net.dnsLookup(domain);
        const endTime2 = Date.now();
        const time2 = endTime2 - startTime2;

        const addresses2Arr = lookup2.addresses || [];
        details.push(`\nSecond DNS lookup (after 2s):`);
        details.push(`  Resolved to: ${addresses2Arr.join(', ')}`);
        details.push(`  Time: ${time2}ms`);

        const addresses1 = new Set(addresses1Arr);
        const addresses2 = new Set(addresses2Arr);
        const addressesChanged =
          ![...addresses1].every((addr) => addresses2.has(addr)) ||
          [...addresses2].every((addr) => addresses1.has(addr));

        if (addressesChanged) {
          vulnerable = true;
          details.push(`\nVULNERABILITY DETECTED!`);
          details.push(`DNS records changed between requests`);
          details.push(`This indicates DNS rebinding is possible`);
        } else {
          details.push(`\nDNS records remained consistent`);
        }

        const allAddresses = [...addresses1Arr, ...addresses2Arr];
        for (const addr of allAddresses) {
          if (addr.match(/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)/)) {
            vulnerable = true;
            details.push(`Resolves to private IP: ${addr}`);
            details.push(`DNS rebinding could access internal network!`);
          }
        }

        if (lookup1.ttl && lookup1.ttl < 60) {
          details.push(`Very low TTL (${lookup1.ttl}s) - facilitates rebinding`);
          vulnerable = true;
        }

        const rebindTime = time2 - time1;

        mitigation.push('Validate Host header in web applications');
        mitigation.push('Use DNS pinning on client side');
        mitigation.push('Implement firewall rules for private IPs');
        mitigation.push('Set minimum TTL values (>60 seconds)');
        mitigation.push('Use DNS security extensions (DNSSEC)');

        if (vulnerable) {
          mitigation.push('\nCRITICAL: Block access to private IPs from public hosts');
        }

        const testResult: RebindingTest = {
          vulnerable,
          timingAnalysis: {
            firstRequest: time1,
            secondRequest: time2,
            rebindTime,
          },
          details,
          mitigation,
        };

        setResult(testResult);
        addToolResult({
          id: Date.now().toString(),
          toolName: 'DNS Rebind',
          input: { domain, targetIP },
          output: testResult,
          success: true,
          timestamp: Date.now(),
        });
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : 'Unknown error';
        details.push(`DNS lookup failed: ${errorMsg}`);

        setResult({
          vulnerable: false,
          timingAnalysis: {
            firstRequest: 0,
            secondRequest: 0,
            rebindTime: 0,
          },
          details,
          mitigation: ['Unable to test - ensure domain is accessible'],
        });
      }
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setResult({
        vulnerable: false,
        timingAnalysis: {
          firstRequest: 0,
          secondRequest: 0,
          rebindTime: 0,
        },
        details: [`Error: ${errorMsg}`],
        mitigation: [],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="DNS Rebinding Attack Analyzer"
      icon={<NetworkIcon />}
      description="Test domains for DNS rebinding vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Domain to Test</label>
          <input
            type="text"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="suspicious-domain.com"
            className={styles.input}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Target Internal IP (for detection)</label>
          <input
            type="text"
            value={targetIP}
            onChange={(e) => setTargetIP(e.target.value)}
            placeholder="127.0.0.1 or 192.168.1.1"
            className={styles.input}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={testRebinding}
            disabled={loading || !domain}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test DNS Rebinding'
            )}
          </button>
        </div>
      </div>

      {result && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>DNS Rebinding Test Results</span>
          </div>

          <div className={styles.resultItem}>
            <strong>Vulnerability Status:</strong>{' '}
            <span className={result.vulnerable ? styles.textError : styles.textSuccess}>
              {result.vulnerable ? 'VULNERABLE' : 'Not Vulnerable'}
            </span>
          </div>

          <div className={styles.resultItem}>
            <strong>Timing Analysis:</strong>
            <div style={{ marginTop: '8px' }}>
              <div>First Request: {result.timingAnalysis.firstRequest}ms</div>
              <div>Second Request: {result.timingAnalysis.secondRequest}ms</div>
              <div>Rebind Window: {result.timingAnalysis.rebindTime}ms</div>
            </div>
          </div>

          <div className={styles.resultItem}>
            <strong>Test Details:</strong>
            <pre className={styles.codeBlock}>{result.details.join('\n')}</pre>
          </div>

          <div className={styles.resultItem}>
            <strong>Mitigation Recommendations:</strong>
            <ul style={{ margin: '8px 0 0 20px' }}>
              {result.mitigation.map((rec, idx) => (
                <li
                  key={idx}
                  style={{
                    color: rec.includes('CRITICAL') ? '#ff6b8a' : 'inherit',
                    fontWeight: rec.includes('CRITICAL') ? 'bold' : 'normal',
                  }}
                >
                  {rec}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
}
