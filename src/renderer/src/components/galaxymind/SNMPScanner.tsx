import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { NetworkIcon, LoadingIcon } from '../common/Icons';

const SNMPScanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [host, setHost] = useState('');
  const [port, setPort] = useState('161');
  const [results, setResults] = useState<Array<{ community: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const communities = ['public', 'private', 'community', 'manager'];

  const testSNMP = async () => {
    if (!host.trim()) {
      setError('Host is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ community: string; result: string }> = [];
      const portNum = parseInt(port);

      try {
        const result = await window.electronAPI.net.scanPort(host, portNum);
        found.push({ community: 'Port Check', result: result.isOpen ? 'OPEN' : 'Closed' });
      } catch {
        found.push({ community: 'Port Check', result: 'Error' });
      }

      for (const community of communities) {
        found.push({ community, result: 'Requires manual testing' });
      }

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'SNMP Scanner',
        timestamp: Date.now(),
        input: { host, port },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'SNMP scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="SNMP Scanner"
      icon={<NetworkIcon />}
      description="Scan SNMP ports and test community strings"
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
            placeholder="161"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testSNMP} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan SNMP'
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
          <span>Testing SNMP...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <h3 className={styles.sectionTitle}>SNMP Results</h3>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.community}
              </span>
              <span style={{ color: '#888', marginLeft: '10px' }}>{result.result}</span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default SNMPScanner;
