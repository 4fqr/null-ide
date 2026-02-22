import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ServerIcon, LoadingIcon } from '../common/Icons';

export default function CloudMetadata() {
  const { addToolResult } = useStore();
  const [targetHost, setTargetHost] = useState('');
  const [results, setResults] = useState<
    Array<{ provider: string; endpoint: string; accessible: boolean }>
  >([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const metadataEndpoints = [
    { provider: 'AWS', endpoint: 'http://169.254.169.254/latest/meta-data/' },
    { provider: 'AWS (IMDSv2)', endpoint: 'http://169.254.169.254/latest/api/token' },
    { provider: 'Google Cloud', endpoint: 'http://metadata.google.internal/computeMetadata/v1/' },
    {
      provider: 'Azure',
      endpoint: 'http://169.254.169.254/metadata/instance?api-version=2021-02-01',
    },
    { provider: 'DigitalOcean', endpoint: 'http://169.254.169.254/metadata/v1/' },
    { provider: 'Oracle Cloud', endpoint: 'http://169.254.169.254/opc/v1/instance/' },
    { provider: 'Alibaba Cloud', endpoint: 'http://100.100.100.200/latest/meta-data/' },
  ];

  const testMetadata = async () => {
    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ provider: string; endpoint: string; accessible: boolean }> = [];

      for (const { provider, endpoint } of metadataEndpoints) {
        try {
          const result = await window.electronAPI.net.httpFetch(endpoint, {
            method: 'GET',
            headers: provider === 'Google Cloud' ? { 'Metadata-Flavor': 'Google' } : {},
            timeout: 3000,
          });

          const accessible = result.status === 200;
          found.push({ provider, endpoint, accessible });
        } catch {
          found.push({ provider, endpoint, accessible: false });
        }

        await new Promise((resolve) => setTimeout(resolve, 200));
      }

      if (targetHost) {
        try {
          const ssrfUrl = `${targetHost}?url=${encodeURIComponent('http://169.254.169.254/latest/meta-data/')}`;
          const result = await window.electronAPI.net.httpFetch(ssrfUrl, {
            method: 'GET',
            timeout: 5000,
          });

          if (result.status === 200) {
            found.push({
              provider: 'SSRF to Metadata',
              endpoint: ssrfUrl,
              accessible: true,
            });
          }
        } catch {
          void 0;
        }
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Cloud Metadata Scanner',
        timestamp: Date.now(),
        input: { targetHost: targetHost || 'Direct' },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Metadata scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Cloud Metadata Scanner"
      icon={<ServerIcon />}
      description="Test for exposed cloud metadata endpoints"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target Host (optional, for SSRF test)</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://target.com/api"
            value={targetHost}
            onChange={(e) => setTargetHost(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testMetadata} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan Metadata'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing cloud metadata endpoints...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Metadata Endpoint Results</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div>
                <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                  {result.provider}
                </span>
                <span style={{ color: result.accessible ? '#ff6b8a' : '#888', marginLeft: '10px' }}>
                  {result.accessible ? 'ACCESSIBLE!' : 'Not Accessible'}
                </span>
              </div>
              <span style={{ color: '#666', fontSize: '10px', marginTop: '2px', display: 'block' }}>
                {result.endpoint}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
