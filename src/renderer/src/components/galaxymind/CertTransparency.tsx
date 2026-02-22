import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

export default function CertTransparency() {
  const { addToolResult } = useStore();
  const [domain, setDomain] = useState('');
  const [results, setResults] = useState<Array<{ log: string; certs: number }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const searchCTLogs = async () => {
    if (!domain.trim()) {
      setError('Domain is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ log: string; certs: number }> = [];
      const ctLogs = ['https://crt.sh/?q=%25.' + domain, 'https://censys.io/domain/' + domain];

      for (const log of ctLogs) {
        try {
          const result = await window.electronAPI.net.httpFetch(log, {
            method: 'GET',
            timeout: 5000,
          });

          const content = String(result);
          const matches = content.match(/<td>.*?<\/td>/g);
          found.push({ log, certs: matches ? matches.length : 0 });
        } catch {
          found.push({ log, certs: 0 });
        }
      }

      setResults(found);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Certificate Transparency',
        timestamp: Date.now(),
        input: { domain },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'CT search failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Certificate Transparency Logs"
      icon={<ShieldIcon />}
      description="Search certificate transparency logs for domain certificates"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Domain</label>
          <input
            type="text"
            className={styles.input}
            placeholder="example.com"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={searchCTLogs} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Searching...
              </>
            ) : (
              'Search CT Logs'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Searching certificate transparency logs...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Certificate Transparency Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                {result.log}
              </span>
              <span style={{ color: '#888', marginLeft: '10px' }}>{result.certs} results</span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
