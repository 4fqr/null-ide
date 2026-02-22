import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { FileIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

interface HeaderInfo {
  name: string;
  value: string;
  security: 'good' | 'warning' | 'missing';
}

export default function HeaderAnalyzer() {
  const [url, setUrl] = useState('');
  const [headers, setHeaders] = useState<HeaderInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const analyzeSecurityHeader = (name: string, value: string): 'good' | 'warning' | 'missing' => {
    const lowerName = name.toLowerCase();
    if (lowerName === 'strict-transport-security' && value.includes('max-age')) return 'good';
    if (lowerName === 'content-security-policy') return 'good';
    if (lowerName === 'x-frame-options' && (value === 'DENY' || value === 'SAMEORIGIN'))
      return 'good';
    if (lowerName === 'x-content-type-options' && value === 'nosniff') return 'good';
    if (lowerName === 'x-xss-protection') return value === '1; mode=block' ? 'good' : 'warning';
    return 'warning';
  };

  const analyze = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    setLoading(true);
    setError('');
    setHeaders([]);

    try {
      const response = await window.electronAPI.net.httpFetch(url, { method: 'GET' });
      if (!response.success) {
        throw new Error(response.error || 'Failed to fetch headers');
      }

      const headersList: HeaderInfo[] = [];

      if (response.headers) {
        Object.keys(response.headers).forEach((key) => {
          headersList.push({
            name: key,
            value: response.headers?.[key] || '',
            security: analyzeSecurityHeader(key, response.headers?.[key] || ''),
          });
        });
      }

      const securityHeaders = [
        'strict-transport-security',
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'x-xss-protection',
      ];

      securityHeaders.forEach((header) => {
        if (!headersList.find((h) => h.name.toLowerCase() === header)) {
          headersList.push({ name: header, value: 'NOT SET', security: 'missing' });
        }
      });

      setHeaders(headersList);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  const getSecurityBadge = (sec: 'good' | 'warning' | 'missing') => {
    const classes = {
      good: styles.badgeSuccess,
      warning: styles.badgeWarning,
      missing: styles.badgeError,
    };
    return <span className={`${styles.badge} ${classes[sec]}`}>{sec.toUpperCase()}</span>;
  };

  return (
    <ToolWrapper
      title="Header Analyzer"
      icon={<FileIcon />}
      description="Analyze HTTP security headers"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Website URL</label>
          <input
            type="text"
            className={styles.input}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={analyze} disabled={loading}>
            {loading ? 'Analyzing...' : 'Analyze Headers'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setUrl('');
              setHeaders([]);
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {headers.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>HTTP Headers ({headers.length})</span>
          </div>
          <table className={styles.table}>
            <thead>
              <tr>
                <th>Header</th>
                <th>Value</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {headers.map((h, i) => (
                <tr key={i}>
                  <td>{h.name}</td>
                  <td className={styles.code} style={{ maxWidth: '300px', wordBreak: 'break-all' }}>
                    {h.value}
                  </td>
                  <td>{getSecurityBadge(h.security)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>Security Headers</h3>
        <ul>
          <li>
            <strong>HSTS:</strong> Forces HTTPS connections
          </li>
          <li>
            <strong>CSP:</strong> Prevents XSS attacks
          </li>
          <li>
            <strong>X-Frame-Options:</strong> Prevents clickjacking
          </li>
          <li>
            <strong>X-Content-Type-Options:</strong> Prevents MIME sniffing
          </li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
