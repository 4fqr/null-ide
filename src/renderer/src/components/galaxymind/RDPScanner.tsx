import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { NetworkIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

const RDPScanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('3389');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testRDP = async () => {
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
        const result = await window.electronAPI.net.scanPort(host, portNum);
        found.push({ test: 'RDP Port', result: result.isOpen ? 'OPEN' : 'Closed' });
      } catch {
        found.push({ test: 'RDP Port', result: 'Error' });
      }

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'RDP Scanner',
        timestamp: Date.now(),
        input: { host, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'RDP scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="RDP Scanner"
      icon={<NetworkIcon />}
      description="Scan for RDP service availability"
    >
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
          placeholder="3389"
          value={port}
          onChange={(e) => setPort(e.target.value)}
        />
      </div>
      <button className={styles.primaryBtn} onClick={testRDP} disabled={loading}>
        {loading ? (
          <>
            <LoadingIcon /> Scanning...
          </>
        ) : (
          'Scan RDP'
        )}
      </button>
      {error && <div className={styles.errorBox}>{error}</div>}
      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing RDP...</span>
        </div>
      )}
      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>RDP Results</span>
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

export default RDPScanner;
