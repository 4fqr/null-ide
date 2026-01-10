import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

interface HeaderInfo {
  name: string;
  value: string;
  security?: 'good' | 'warning' | 'missing';
}

const HeaderAnalyzer: React.FC = () => {
  const { setActiveGalaxyTool, addToolResult } = useStore();
  const [url, setUrl] = useState('');
  const [headers, setHeaders] = useState<HeaderInfo[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const analyzeHeaders = async () => {
    if (!url.trim()) {
      setError('URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setHeaders([]);

    try {
      const response: any = await window.electronAPI.net.httpFetch(url, { method: 'GET' });
      
      if (!response.success) {
        throw new Error(response.error || 'Failed to fetch headers');
      }

      const headersList: HeaderInfo[] = [];

      // Add all headers from response
      Object.keys(response.headers).forEach((key) => {
        headersList.push({
          name: key,
          value: response.headers[key],
          security: analyzeSecurityHeader(key, response.headers[key]),
        });
      });

      // Check for missing security headers
      const securityHeaders = [
        'strict-transport-security',
        'content-security-policy',
        'x-frame-options',
        'x-content-type-options',
        'x-xss-protection',
      ];

      securityHeaders.forEach((header) => {
        if (!headersList.find((h) => h.name.toLowerCase() === header)) {
          headersList.push({
            name: header,
            value: 'NOT SET',
            security: 'missing',
          });
        }
      });

      setHeaders(headersList);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Header Analyzer',
        timestamp: Date.now(),
        input: { url },
        output: headersList,
        success: true,
      });
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Analysis failed';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  const analyzeSecurityHeader = (name: string, value: string): 'good' | 'warning' | 'missing' => {
    const lowerName = name.toLowerCase();

    if (lowerName === 'strict-transport-security' && value.includes('max-age')) return 'good';
    if (lowerName === 'content-security-policy') return 'good';
    if (lowerName === 'x-frame-options' && (value === 'DENY' || value === 'SAMEORIGIN')) return 'good';
    if (lowerName === 'x-content-type-options' && value === 'nosniff') return 'good';
    if (lowerName === 'x-xss-protection') return value === '1; mode=block' ? 'good' : 'warning';

    return 'warning';
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <h2 className={styles.toolTitle}>
          <span className={styles.toolIcon}>📑</span>
          Header Analyzer
        </h2>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Website URL</label>
            <input
              type="text"
              className={styles.input}
              placeholder="https://example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </div>

          <button className={styles.sendButton} onClick={analyzeHeaders} disabled={loading}>
            {loading ? 'Analyzing...' : 'Analyze Headers'}
          </button>
        </div>

        {error && (
          <div className={styles.error}>
            <strong>Error:</strong> {error}
          </div>
        )}

        {loading && (
          <div className={styles.loading}>
            <div className={styles.spinner}></div>
            <span>Analyzing HTTP headers...</span>
          </div>
        )}

        {headers.length > 0 && (
          <div className={styles.results}>
            <h3 className={styles.sectionTitle}>HTTP Headers ({headers.length})</h3>
            {headers.map((header, index) => (
              <div key={index} className={styles.resultItem}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <strong style={{ color: '#00ffaa' }}>{header.name}</strong>
                    {header.security && (
                      <span
                        style={{
                          padding: '2px 8px',
                          borderRadius: '4px',
                          fontSize: 'var(--font-size-xs)',
                          fontWeight: '700',
                          background:
                            header.security === 'good'
                              ? 'rgba(76, 175, 80, 0.2)'
                              : header.security === 'warning'
                              ? 'rgba(255, 152, 0, 0.2)'
                              : 'rgba(244, 67, 54, 0.2)',
                          color:
                            header.security === 'good' ? '#4caf50' : header.security === 'warning' ? '#ff9800' : '#f44336',
                          border: `1px solid ${
                            header.security === 'good' ? '#4caf50' : header.security === 'warning' ? '#ff9800' : '#f44336'
                          }`,
                        }}
                      >
                        {header.security.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <span
                    style={{
                      color: header.value === 'NOT SET' ? '#f44336' : '#9a9aad',
                      fontFamily: 'var(--font-mono)',
                      fontSize: 'var(--font-size-sm)',
                      wordBreak: 'break-all',
                    }}
                  >
                    {header.value}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default HeaderAnalyzer;
