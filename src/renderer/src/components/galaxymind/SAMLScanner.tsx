import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { LockIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

const SAMLScanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [samlUrl, setSamlUrl] = useState('');
  const [results, setResults] = useState<Array<{ issue: string; severity: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testSAML = async () => {
    if (!samlUrl.trim()) {
      setError('SAML endpoint URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ issue: string; severity: string }> = [];

      const result = await window.electronAPI.net.httpFetch(samlUrl, {
        method: 'GET',
        timeout: 5000,
      });

      const response = String(result);

      if (
        response.toLowerCase().includes('<signature>') ||
        response.toLowerCase().includes('signature')
      ) {
        found.push({ issue: 'SAML Signatures Present', severity: 'Good' });
      } else {
        found.push({ issue: 'No Signature Found', severity: 'Critical' });
      }

      const xmlPayloads = ['<!ENTITY xxe SYSTEM "file:///etc/passwd">', '<![CDATA[attack]]>'];

      for (const payload of xmlPayloads) {
        const testSaml = `<samlp:Response>${payload}</samlp:Response>`;
        try {
          await window.electronAPI.net.httpFetch(samlUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/xml' },
            body: testSaml,
            timeout: 3000,
          });
        } catch {
          void 0;
        }
      }

      if (response.includes('<!--') || response.includes('-->')) {
        found.push({ issue: 'XML Comments in Response', severity: 'Low' });
      }

      found.push({ issue: 'Assertion Replay Protection', severity: 'Manual Test Required' });

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'SAML Scanner',
        timestamp: Date.now(),
        input: { samlUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'SAML test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="SAML Scanner"
      icon={<LockIcon />}
      description="Test SAML endpoints for security vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>SAML Endpoint URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/saml/sso"
            value={samlUrl}
            onChange={(e) => setSamlUrl(e.target.value)}
          />
        </div>

        <button className={styles.primaryBtn} onClick={testSAML} disabled={loading}>
          {loading ? (
            <>
              <LoadingIcon /> Scanning...
            </>
          ) : (
            'Scan SAML'
          )}
        </button>
      </div>

      {error && (
        <div className={styles.errorBox}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing SAML configuration...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultTitle}>SAML Security Findings</div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.issue}
              </span>
              <span
                style={{
                  color:
                    result.severity === 'Critical'
                      ? '#ff4444'
                      : result.severity === 'Good'
                        ? '#00ff00'
                        : '#888',
                  marginLeft: '10px',
                }}
              >
                [{result.severity}]
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default SAMLScanner;
