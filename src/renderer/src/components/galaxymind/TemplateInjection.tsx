import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

const TemplateInjection: React.FC = () => {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [paramName, setParamName] = useState('name');
  const [results, setResults] = useState<
    Array<{ engine: string; payload: string; result: string }>
  >([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const templatePayloads = [
    { engine: 'Jinja2', payload: '{{7*7}}', expected: '49' },
    { engine: 'Jinja2', payload: '{{config.items()}}', expected: 'config' },
    { engine: 'Twig', payload: '{{7*7}}', expected: '49' },
    { engine: 'Twig', payload: '{{_self.env.display()}}', expected: 'display' },
    { engine: 'Freemarker', payload: '${7*7}', expected: '49' },
    { engine: 'Freemarker', payload: '${7*"7"}', expected: '7777777' },
    { engine: 'Velocity', payload: '#set($x=7*7)$x', expected: '49' },
    { engine: 'Smarty', payload: '{7*7}', expected: '49' },
    { engine: 'ERB', payload: '<%= 7*7 %>', expected: '49' },
  ];

  const testSSTI = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ engine: string; payload: string; result: string }> = [];

      for (const { engine, payload, expected } of templatePayloads) {
        try {
          const testUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}${paramName}=${encodeURIComponent(payload)}`;

          const result = await window.electronAPI.net.httpFetch(testUrl, {
            method: 'GET',
            timeout: 5000,
          });

          const vulnerable = result.data && result.data.includes(expected);
          found.push({
            engine,
            payload,
            result: vulnerable ? 'VULNERABLE!' : 'Safe',
          });
        } catch (err) {
          found.push({ engine, payload, result: 'Error' });
        }

        await new Promise((resolve) => setTimeout(resolve, 200));
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Template Injection',
        timestamp: Date.now(),
        input: { targetUrl, paramName },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'SSTI test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Template Injection Scanner"
      icon={<ShieldIcon />}
      description="Detect Server-Side Template Injection (SSTI) vulnerabilities in web applications"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/page"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Parameter Name</label>
          <input
            type="text"
            className={styles.input}
            placeholder="name"
            value={paramName}
            onChange={(e) => setParamName(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testSSTI} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test SSTI'
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
          <span>Testing template engines...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultTitle}>SSTI Test Results</div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div className={styles.resultRow}>
                <span className={styles.resultValue}>{result.engine}</span>
                <span style={{ color: '#666', fontSize: '12px' }}>{result.payload}</span>
                <span
                  className={
                    result.result.includes('VULNERABLE') ? styles.textError : styles.textSuccess
                  }
                >
                  {result.result}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default TemplateInjection;
