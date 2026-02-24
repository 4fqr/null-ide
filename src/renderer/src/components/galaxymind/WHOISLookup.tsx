import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { WhoIsIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

interface WHOISData {
  domain: string;
  registrar: string;
  created: string;
  expires: string;
  status: string;
  nameservers: string[];
}

export default function WHOISLookup() {
  const [domain, setDomain] = useState('');
  const [data, setData] = useState<WHOISData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const lookup = async () => {
    if (!domain.trim()) {
      setError('Please enter a domain');
      return;
    }

    setLoading(true);
    setError('');
    setData(null);

    try {
      const response = await window.electronAPI.net.whoisLookup(domain);

      if (!response.success || !response.data) {
        throw new Error(response.error || 'WHOIS lookup failed');
      }

      setData(response.data);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'WHOIS lookup failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="WHOIS Lookup"
      icon={<WhoIsIcon />}
      description="Look up domain registration information"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Domain Name</label>
          <input
            type="text"
            className={styles.input}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="example.com"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={lookup} disabled={loading}>
            {loading ? 'Looking up...' : 'Lookup WHOIS'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setDomain('');
              setData(null);
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {data && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>WHOIS Information</span>
          </div>
          <table className={styles.table}>
            <tbody>
              <tr>
                <td>
                  <strong>Domain</strong>
                </td>
                <td>{data.domain || 'N/A'}</td>
              </tr>
              <tr>
                <td>
                  <strong>Registrar</strong>
                </td>
                <td>{data.registrar}</td>
              </tr>
              <tr>
                <td>
                  <strong>Created</strong>
                </td>
                <td>{data.created}</td>
              </tr>
              <tr>
                <td>
                  <strong>Expires</strong>
                </td>
                <td>{data.expires}</td>
              </tr>
              <tr>
                <td>
                  <strong>Status</strong>
                </td>
                <td>{data.status}</td>
              </tr>
              {data.nameservers.length > 0 && (
                <tr>
                  <td>
                    <strong>Nameservers</strong>
                  </td>
                  <td>{data.nameservers.join(', ')}</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>WHOIS Information</h3>
        <ul>
          <li>Shows domain registration details</li>
          <li>Useful for OSINT and reconnaissance</li>
          <li>Direct WHOIS protocol query (no rate limits)</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
