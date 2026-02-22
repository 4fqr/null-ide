import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { NetworkIcon, LoadingIcon } from '../common/Icons';

const LDAPScanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('389');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testLDAP = async () => {
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
        found.push({ test: 'LDAP Port', result: result.isOpen ? 'OPEN' : 'Closed' });
      } catch {
        found.push({ test: 'LDAP Port', result: 'Error' });
      }

      try {
        const result = await window.electronAPI.net.scanPort(host, 636);
        found.push({ test: 'LDAPS Port (636)', result: result.isOpen ? 'OPEN' : 'Closed' });
      } catch {
        found.push({ test: 'LDAPS Port (636)', result: 'Error' });
      }

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'LDAP Scanner',
        timestamp: Date.now(),
        input: { host, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'LDAP scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="LDAP Scanner"
      icon={<NetworkIcon />}
      description="Scan for LDAP services and open ports"
    >
      <div className={styles.section}>
        <div className={styles.grid2} style={{ display: 'grid', gap: '16px' }}>
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
              placeholder="389"
              value={port}
              onChange={(e) => setPort(e.target.value)}
            />
          </div>
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testLDAP} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon />
                Scanning...
              </>
            ) : (
              'Scan LDAP'
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
          <span>Testing LDAP...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>LDAP Results</span>
          </div>
          <div className={styles.resultContent}>
            {results.map((result, idx) => (
              <div key={idx} className={styles.resultItem}>
                <div className={styles.resultRow}>
                  <span className={styles.resultLabel}>{result.test}</span>
                  <span
                    className={styles.resultValue}
                    style={{ color: result.result.includes('OPEN') ? '#ff6b8a' : undefined }}
                  >
                    {result.result}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default LDAPScanner;
