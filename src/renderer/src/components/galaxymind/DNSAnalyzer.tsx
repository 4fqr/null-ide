import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { GlobeIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

interface DNSRecord {
  type: string;
  name: string;
  value: string;
}

export default function DNSAnalyzer() {
  const [hostname, setHostname] = useState('');
  const [records, setRecords] = useState<DNSRecord[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleLookup = async () => {
    if (!hostname.trim()) {
      setError('Please enter a hostname');
      return;
    }

    setLoading(true);
    setError('');
    setRecords([]);

    try {
      const result = await window.electronAPI.net.dnsLookup(hostname);
      if (result.success && result.addresses) {
        const dnsRecords: DNSRecord[] = result.addresses.map((addr: string) => ({
          type: 'A',
          name: hostname,
          value: addr,
        }));

        try {
          const firstAddr = result.addresses[0];
          if (firstAddr) {
            const reverseResult = await window.electronAPI.net.reverseDns(firstAddr);
            if (reverseResult.success && reverseResult.hostnames) {
              reverseResult.hostnames.forEach((h: string) => {
                dnsRecords.push({ type: 'PTR', name: firstAddr, value: h });
              });
            }
          }
        } catch {}

        setRecords(dnsRecords);
      } else {
        setError('No DNS records found');
      }
    } catch (err) {
      setError('DNS lookup failed: ' + (err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="DNS Analyzer"
      icon={<GlobeIcon />}
      description="Perform DNS lookups and analyze domain records"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Hostname</label>
          <input
            type="text"
            className={styles.input}
            value={hostname}
            onChange={(e) => setHostname(e.target.value)}
            placeholder="e.g., example.com"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={handleLookup} disabled={loading}>
            {loading ? 'Looking up...' : 'Lookup DNS'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setHostname('');
              setRecords([]);
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {records.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>DNS Records ({records.length})</span>
            <button
              className={styles.copyBtn}
              onClick={() => navigator.clipboard.writeText(JSON.stringify(records, null, 2))}
            >
              Copy
            </button>
          </div>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Type</th>
                <th>Name</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              {records.map((record, i) => (
                <tr key={i}>
                  <td>
                    <span className={`${styles.badge} ${styles.badgeInfo}`}>{record.type}</span>
                  </td>
                  <td>{record.name}</td>
                  <td className={styles.code}>{record.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>DNS Analysis Tips</h3>
        <ul>
          <li>DNS records reveal server infrastructure</li>
          <li>Look for unusual record types (TXT, SRV)</li>
          <li>Check for subdomain enumeration possibilities</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
