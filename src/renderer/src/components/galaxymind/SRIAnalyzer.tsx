import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

const SRIAnalyzer: React.FC = () => {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<
    Array<{ resource: string; hasSRI: boolean; integrity?: string }>
  >([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyzeSRI = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const result = await window.electronAPI.net.httpFetch(targetUrl, {
        method: 'GET',
        timeout: 5000,
      });

      const html = String(result);
      const found: Array<{ resource: string; hasSRI: boolean; integrity?: string }> = [];

      const scriptMatches = html.match(/<script[^>]+src=["']([^"']+)["'][^>]*>/gi) || [];
      for (const match of scriptMatches) {
        const srcMatch = match.match(/src=["']([^"']+)["']/);
        const integrityMatch = match.match(/integrity=["']([^"']+)["']/);

        if (srcMatch) {
          found.push({
            resource: srcMatch[1],
            hasSRI: !!integrityMatch,
            integrity: integrityMatch ? integrityMatch[1] : undefined,
          });
        }
      }

      const linkMatches = html.match(/<link[^>]+href=["']([^"']+)["'][^>]*>/gi) || [];
      for (const match of linkMatches) {
        if (match.includes('stylesheet')) {
          const hrefMatch = match.match(/href=["']([^"']+)["']/);
          const integrityMatch = match.match(/integrity=["']([^"']+)["']/);

          if (hrefMatch) {
            found.push({
              resource: hrefMatch[1],
              hasSRI: !!integrityMatch,
              integrity: integrityMatch ? integrityMatch[1] : undefined,
            });
          }
        }
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'SRI Analyzer',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'SRI analysis failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="SRI Analyzer"
      icon={<ShieldIcon />}
      description="Check subresource integrity for external scripts and stylesheets"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={analyzeSRI} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Analyzing...
              </>
            ) : (
              'Analyze SRI'
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
          <span>Analyzing subresource integrity...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <h3 className={styles.sectionTitle}>External Resources</h3>
          {results.map((result, idx) => (
            <div
              key={idx}
              className={styles.resultItem}
              style={{ flexDirection: 'column', alignItems: 'flex-start' }}
            >
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                {result.resource}
              </span>
              <span
                style={{
                  color: result.hasSRI ? '#888' : '#ff4444',
                  marginLeft: '10px',
                  fontSize: '12px',
                }}
              >
                {result.hasSRI ? `✓ SRI: ${result.integrity}` : '✗ No SRI'}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default SRIAnalyzer;
