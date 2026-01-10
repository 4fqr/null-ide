import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

interface ScanResult {
  port: number;
  state: 'open' | 'closed' | 'filtered';
  service?: string;
}

const PortScanner: React.FC = () => {
  const { setActiveGalaxyTool, addToolResult } = useStore();
  const [host, setHost] = useState('');
  const [ports, setPorts] = useState('80,443,8080');
  const [results, setResults] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

  const scanPorts = async () => {
    if (!host.trim()) {
      setError('Host is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);
    setProgress(0);

    try {
      const portList = ports.split(',').map((p) => parseInt(p.trim())).filter((p) => !isNaN(p) && p > 0 && p <= 65535);

      if (portList.length === 0) {
        setError('No valid ports specified');
        setLoading(false);
        return;
      }

      const scanResults: ScanResult[] = [];

      for (let i = 0; i < portList.length; i++) {
        const port = portList[i];
        setProgress(Math.round(((i + 1) / portList.length) * 100));

        try {
          // Use Electron IPC for actual port scanning
          const result = await window.electronAPI.net.scanPort(host, port, 2000);
          
          if (result.success && result.isOpen) {
            scanResults.push({
              port,
              state: 'open',
              service: getServiceName(port),
            });
          } else {
            scanResults.push({ port, state: 'closed' });
          }
        } catch (err: any) {
          scanResults.push({ port, state: 'filtered' });
        }

        // Small delay to prevent overwhelming
        await new Promise((resolve) => setTimeout(resolve, 50));
      }

      setResults(scanResults);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Port Scanner',
        timestamp: Date.now(),
        input: { host, ports: portList },
        output: scanResults,
        success: true,
      });
    } catch (err: any) {
      setError(err.message || 'Scan failed');
    } finally {
      setLoading(false);
      setProgress(0);
    }
  };

  const getServiceName = (port: number): string => {
    const services: Record<number, string> = {
      20: 'FTP-DATA',
      21: 'FTP',
      22: 'SSH',
      23: 'TELNET',
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
      8080: 'HTTP-Proxy',
      8443: 'HTTPS-Alt',
    };
    return services[port] || 'Unknown';
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <h2 className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔍</span>
          Port Scanner
        </h2>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Target Host</label>
            <input
              type="text"
              className={styles.input}
              placeholder="example.com or 192.168.1.1"
              value={host}
              onChange={(e) => setHost(e.target.value)}
            />
          </div>

          <div className={styles.inputGroup}>
            <label className={styles.label}>Ports (comma-separated)</label>
            <input
              type="text"
              className={styles.input}
              placeholder="80,443,8080"
              value={ports}
              onChange={(e) => setPorts(e.target.value)}
            />
          </div>

          <button className={styles.sendButton} onClick={scanPorts} disabled={loading}>
            {loading ? `Scanning... ${progress}%` : 'Start Scan'}
          </button>
        </div>

        {error && (
          <div className={styles.error}>
            <strong>Error:</strong> {error}
          </div>
        )}

        {loading && (
          <div className={styles.loading}>
            <div className={styles.spinner}></div>
            <span>Scanning ports... {progress}%</span>
          </div>
        )}

        {results.length > 0 && (
          <div className={styles.results}>
            <h3 className={styles.sectionTitle}>Scan Results ({results.length} ports)</h3>
            {results.map((result) => (
              <div key={result.port} className={styles.resultItem}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <strong style={{ color: '#00ffaa' }}>Port {result.port}</strong>
                    {result.service && <span style={{ color: '#9a9aad' }}> ({result.service})</span>}
                  </div>
                  <span
                    style={{
                      padding: '4px 12px',
                      borderRadius: '6px',
                      fontSize: 'var(--font-size-sm)',
                      fontWeight: '700',
                      background:
                        result.state === 'open'
                          ? 'rgba(76, 175, 80, 0.2)'
                          : result.state === 'filtered'
                          ? 'rgba(255, 152, 0, 0.2)'
                          : 'rgba(244, 67, 54, 0.2)',
                      color:
                        result.state === 'open'
                          ? '#4caf50'
                          : result.state === 'filtered'
                          ? '#ff9800'
                          : '#f44336',
                      border: `1px solid ${
                        result.state === 'open'
                          ? '#4caf50'
                          : result.state === 'filtered'
                          ? '#ff9800'
                          : '#f44336'
                      }`,
                    }}
                  >
                    {result.state.toUpperCase()}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default PortScanner;
