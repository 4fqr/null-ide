import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { NetworkIcon, LoadingIcon } from '../common/Icons';

const FTPScanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('21');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testFTP = async () => {
    if (!host.trim()) {
      setError('Host is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ test: string; result: string }> = [];
      const portNum = parseInt(port);

      try {
        const scanResult = await window.electronAPI.net.scanPort(host, portNum);
        found.push({ test: 'FTP Port', result: scanResult.isOpen ? 'OPEN' : 'Closed' });
      } catch {
        found.push({ test: 'FTP Port', result: 'Error' });
      }

      try {
        await window.electronAPI.net.httpFetch(`ftp://${host}`, {
          method: 'GET',
          timeout: 3000,
        });
        found.push({ test: 'FTP Anonymous', result: 'Check manually' });
      } catch {
        found.push({ test: 'FTP Anonymous', result: 'Not accessible' });
      }

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'FTP Scanner',
        timestamp: Date.now(),
        input: { host, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'FTP scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="FTP Scanner"
      icon={<NetworkIcon />}
      description="Scan FTP servers for anonymous access and misconfigurations"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Host</label>
          <input
            type="text"
            className={styles.input}
            placeholder="example.com"
            value={host}
            onChange={(e) => setHost(e.target.value)}
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Port</label>
          <input
            type="text"
            className={styles.input}
            placeholder="21"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testFTP} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan FTP'
            )}
          </button>
        </div>
      </div>
      {error && (
        <div className={styles.errorBox}>
          <strong>Error:</strong> {error}
        </div>
      )}
      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing FTP...</span>
        </div>
      )}
      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>FTP Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.test}
              </span>
              <span
                style={{
                  color: result.result.includes('OPEN') ? '#ff4444' : '#888',
                  marginLeft: '10px',
                }}
              >
                {result.result}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default FTPScanner;
