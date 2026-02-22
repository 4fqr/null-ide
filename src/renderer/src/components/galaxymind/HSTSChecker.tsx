import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

const HSTSChecker: React.FC = () => {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<
    Array<{ check: string; status: string; details?: string }>
  >([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const checkHSTS = async () => {
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

      const headers = result.headers || {};
      const hstsHeader =
        headers['strict-transport-security'] || headers['Strict-Transport-Security'] || '';
      const found: Array<{ check: string; status: string; details?: string }> = [];

      if (hstsHeader) {
        found.push({ check: 'HSTS Header', status: 'Present', details: hstsHeader });

        const maxAgeMatch = hstsHeader.match(/max-age=(\d+)/);
        if (maxAgeMatch) {
          const maxAge = parseInt(maxAgeMatch[1]);
          const days = Math.floor(maxAge / 86400);
          const recommended = maxAge >= 31536000;
          found.push({
            check: 'Max-Age',
            status: recommended ? 'Good' : 'Weak',
            details: `${days} days (${recommended ? '≥' : '<'} 365 recommended)`,
          });
        } else {
          found.push({ check: 'Max-Age', status: 'Missing', details: 'Required' });
        }

        const includesSubdomains = hstsHeader.includes('includeSubDomains');
        found.push({
          check: 'includeSubDomains',
          status: includesSubdomains ? 'Enabled' : 'Disabled',
          details: includesSubdomains ? 'Subdomains protected' : 'Subdomains not protected',
        });

        const preload = hstsHeader.includes('preload');
        found.push({
          check: 'Preload',
          status: preload ? 'Enabled' : 'Disabled',
          details: preload ? 'Browser preload list eligible' : 'Not eligible for preload',
        });
      } else {
        found.push({ check: 'HSTS Header', status: 'MISSING', details: 'Site not using HSTS' });
      }

      const httpUrl = targetUrl.replace('https://', 'http://');
      try {
        const httpResult = await window.electronAPI.net.httpFetch(httpUrl, {
          method: 'GET',
          timeout: 3000,
        });
        const redirects =
          httpResult.status === 301 ||
          httpResult.status === 302 ||
          httpResult.status === 307 ||
          httpResult.status === 308;
        found.push({
          check: 'HTTP → HTTPS Redirect',
          status: redirects ? 'Enabled' : 'Disabled',
          details: redirects ? `Status: ${httpResult.status}` : 'HTTP not redirected',
        });
      } catch {
        found.push({
          check: 'HTTP → HTTPS Redirect',
          status: 'Unknown',
          details: 'Could not test',
        });
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'HSTS Checker',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'HSTS check failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const getStatusClass = (status: string) => {
    if (status === 'MISSING' || status === 'Weak' || status === 'Disabled') {
      return styles.textError;
    }
    if (status === 'Present' || status === 'Good' || status === 'Enabled') {
      return styles.textSuccess;
    }
    return '';
  };

  return (
    <ToolWrapper
      title="HSTS Checker"
      icon={<ShieldIcon />}
      description="Check HTTP Strict Transport Security configuration and best practices"
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
          <button className={styles.primaryBtn} onClick={checkHSTS} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Checking...
              </>
            ) : (
              'Check HSTS'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Checking HSTS configuration...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>HSTS Configuration</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div className={styles.resultRow}>
                <span className={styles.resultLabel}>{result.check}:</span>
                <span className={getStatusClass(result.status)}>{result.status}</span>
              </div>
              {result.details && (
                <div
                  style={{
                    color: 'var(--color-text-tertiary)',
                    fontSize: '11px',
                    marginTop: '4px',
                  }}
                >
                  {result.details}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default HSTSChecker;
