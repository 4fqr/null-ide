import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { NetworkIcon, LoadingIcon } from '../common/Icons';

export default function BGPScanner() {
  const { addToolResult } = useStore();
  const [asn, setAsn] = useState('');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testBGP = async () => {
    if (!asn.trim()) {
      setError('ASN is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ test: string; result: string }> = [];

      try {
        const result = await window.electronAPI.net.httpFetch(`https://bgpview.io/asn/${asn}`, {
          method: 'GET',
          timeout: 5000,
        });
        found.push({ test: 'ASN Lookup', result: result.status === 200 ? 'Found' : 'Not Found' });
      } catch {
        found.push({ test: 'ASN Lookup', result: 'Error' });
      }

      found.push({ test: 'BGP Hijacking Detection', result: 'Requires continuous monitoring' });

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'BGP Scanner',
        timestamp: Date.now(),
        input: { asn },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'BGP scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="BGP Scanner"
      icon={<NetworkIcon />}
      description="Scan BGP routes and detect potential hijacking"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>ASN</label>
          <input
            type="text"
            className={styles.input}
            placeholder="15169"
            value={asn}
            onChange={(e) => setAsn(e.target.value)}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testBGP} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan BGP'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing BGP...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>BGP Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.test}
              </span>
              <span style={{ color: '#888', marginLeft: '10px' }}>{result.result}</span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
