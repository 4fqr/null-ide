import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { LockIcon, LoadingIcon } from '../common/Icons';

const OAuth2Scanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [authUrl, setAuthUrl] = useState('');
  const [redirectUri, setRedirectUri] = useState('');
  const [results, setResults] = useState<
    Array<{ vulnerability: string; severity: string; details: string }>
  >([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testOAuth2 = async () => {
    if (!authUrl.trim()) {
      setError('OAuth2 authorization URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ vulnerability: string; severity: string; details: string }> = [];

      if (!authUrl.startsWith('https://')) {
        found.push({
          vulnerability: 'Insecure Protocol',
          severity: 'High',
          details: 'OAuth2 endpoint not using HTTPS',
        });
      }

      if (!authUrl.includes('state=')) {
        found.push({
          vulnerability: 'Missing State Parameter',
          severity: 'High',
          details: 'No CSRF protection via state parameter',
        });
      }

      if (redirectUri) {
        const openRedirectTests = [
          `${redirectUri}@evil.com`,
          `${redirectUri}.evil.com`,
          `${redirectUri}%2F%2Fevil.com`,
        ];

        for (const testUri of openRedirectTests) {
          const testUrl = authUrl.includes('?')
            ? `${authUrl}&redirect_uri=${encodeURIComponent(testUri)}`
            : `${authUrl}?redirect_uri=${encodeURIComponent(testUri)}`;

          try {
            const result = await window.electronAPI.net.httpFetch(testUrl, {
              method: 'GET',
              timeout: 5000,
            });

            if (result.status === 200 || result.status === 302) {
              found.push({
                vulnerability: 'Open Redirect',
                severity: 'Critical',
                details: `Accepted malformed redirect_uri: ${testUri}`,
              });
            }
          } catch {
            void 0;
          }
        }
      }

      const responseTypes = ['token', 'code', 'id_token'];
      for (const type of responseTypes) {
        const testUrl = authUrl.includes('response_type=')
          ? authUrl.replace(/response_type=[^&]+/, `response_type=${type}`)
          : `${authUrl}${authUrl.includes('?') ? '&' : '?'}response_type=${type}`;

        try {
          await window.electronAPI.net.httpFetch(testUrl, {
            method: 'GET',
            timeout: 3000,
          });
        } catch {
          void 0;
        }
      }

      if (authUrl.includes('response_type=token')) {
        found.push({
          vulnerability: 'Implicit Flow Detected',
          severity: 'Medium',
          details: 'Implicit flow is deprecated, use PKCE instead',
        });
      }

      if (found.length === 0) {
        found.push({
          vulnerability: 'No Issues Found',
          severity: 'Info',
          details: 'Basic OAuth2 security checks passed',
        });
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'OAuth2 Scanner',
        timestamp: Date.now(),
        input: { authUrl, redirectUri },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'OAuth2 test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="OAuth 2.0 Scanner"
      icon={<LockIcon />}
      description="Analyze OAuth2 configurations for security vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>OAuth2 Authorization URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/oauth/authorize?client_id=xxx"
            value={authUrl}
            onChange={(e) => setAuthUrl(e.target.value)}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Redirect URI (optional)</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://yourapp.com/callback"
            value={redirectUri}
            onChange={(e) => setRedirectUri(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testOAuth2} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan OAuth2'
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
          <span>Testing OAuth2 configuration...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <h3 className={styles.resultTitle}>OAuth2 Security Findings</h3>
          {results.map((result, idx) => (
            <div
              key={idx}
              className={styles.resultItem}
              style={{ flexDirection: 'column', alignItems: 'flex-start' }}
            >
              <div>
                <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                  {result.vulnerability}
                </span>
                <span
                  style={{
                    color:
                      result.severity === 'Critical'
                        ? '#ff0000'
                        : result.severity === 'High'
                          ? '#ff4444'
                          : result.severity === 'Medium'
                            ? '#ffaa00'
                            : '#888',
                    marginLeft: '10px',
                    fontSize: '11px',
                  }}
                >
                  [{result.severity}]
                </span>
              </div>
              <span style={{ color: '#666', fontSize: '11px', marginTop: '2px' }}>
                {result.details}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default OAuth2Scanner;
