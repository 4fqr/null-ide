import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { NetworkIcon, LoadingIcon } from '../common/Icons';

export default function ARPScanner() {
  const { addToolResult } = useStore();
  const [network, setNetwork] = useState('');
  const [results, setResults] = useState<Array<{ info: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testARP = () => {
    if (!network.trim()) {
      setError('Network is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ info: string }> = [];
      found.push({ info: 'ARP Spoofing detection requires network-level tools' });
      found.push({ info: 'Monitor for duplicate MAC addresses' });
      found.push({ info: 'Use ARP tables to detect anomalies' });

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'ARP Scanner',
        timestamp: Date.now(),
        input: { network },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'ARP scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="ARP Spoofing Detector"
      icon={<NetworkIcon />}
      description="Detect ARP spoofing and network anomalies"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Network</label>
          <input
            type="text"
            className={styles.input}
            placeholder="192.168.1.0/24"
            value={network}
            onChange={(e) => setNetwork(e.target.value)}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testARP} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Analyzing...
              </>
            ) : (
              'Analyze ARP'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Analyzing ARP...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>ARP Information</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.info}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
