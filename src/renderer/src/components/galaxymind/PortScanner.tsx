import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { SearchIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function PortScanner() {
  const [host, setHost] = useState('');
  const [startPort, setStartPort] = useState(1);
  const [endPort, setEndPort] = useState(100);
  const [results, setResults] = useState<{ port: number; open: boolean; service?: string }[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState(0);

  const commonServices: Record<number, string> = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    445: 'SMB',
    993: 'IMAPS',
    995: 'POP3S',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-Alt',
    8443: 'HTTPS-Alt',
    27017: 'MongoDB',
  };

  const scanPorts = async () => {
    if (!host.trim()) {
      setError('Please enter a host to scan');
      return;
    }

    setLoading(true);
    setError('');
    setResults([]);
    setProgress(0);

    const openPorts: { port: number; open: boolean; service?: string }[] = [];
    const totalPorts = endPort - startPort + 1;
    let scanned = 0;

    for (let port = startPort; port <= endPort; port++) {
      try {
        const res = await window.electronAPI.net.scanPort(host, port, 300);
        if (res.success && res.isOpen) {
          openPorts.push({ port, open: true, service: commonServices[port] });
          setResults([...openPorts]);
        }
      } catch {}
      scanned++;
      setProgress(Math.round((scanned / totalPorts) * 100));
    }

    setLoading(false);
    if (openPorts.length === 0) {
      setError('No open ports found in the specified range');
    }
  };

  return (
    <ToolWrapper
      title="Port Scanner"
      icon={<SearchIcon />}
      description="Scan TCP ports to discover open services"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target Host</label>
          <input
            type="text"
            className={styles.input}
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder="e.g., 192.168.1.1 or example.com"
          />
        </div>
        <div className={styles.flexRow}>
          <div className={styles.flex1}>
            <div className={styles.inputGroup}>
              <label className={styles.label}>Start Port</label>
              <input
                type="number"
                className={styles.input}
                value={startPort}
                onChange={(e) => setStartPort(parseInt(e.target.value) || 1)}
                min={1}
                max={65535}
              />
            </div>
          </div>
          <div className={styles.flex1}>
            <div className={styles.inputGroup}>
              <label className={styles.label}>End Port</label>
              <input
                type="number"
                className={styles.input}
                value={endPort}
                onChange={(e) => setEndPort(parseInt(e.target.value) || 100)}
                min={1}
                max={65535}
              />
            </div>
          </div>
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={scanPorts} disabled={loading}>
            {loading ? `Scanning (${progress}%)` : 'Start Scan'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setHost('');
              setResults([]);
              setError('');
              setProgress(0);
            }}
          >
            Clear
          </button>
        </div>
      </div>
      {loading && (
        <div className={styles.progressBar}>
          <div className={styles.progressFill} style={{ width: `${progress}%` }} />
        </div>
      )}
      {error && <div className={styles.errorBox}>{error}</div>}
      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Open Ports ({results.length})</span>
          </div>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Port</th>
                <th>Service</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr key={i}>
                  <td>{r.port}</td>
                  <td>{r.service || 'Unknown'}</td>
                  <td>
                    <span className={`${styles.badge} ${styles.badgeSuccess}`}>OPEN</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className={styles.infoBox}>
        <h3>About Port Scanning</h3>
        <ul>
          <li>Scans TCP ports to discover open services</li>
          <li>Identifies potential attack surface</li>
          <li>Only scan systems you have permission to test</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
