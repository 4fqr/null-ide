import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

const XSSDetector: React.FC = () => {
  const { setActiveGalaxyTool, addToolResult } = useStore();
  const [url, setUrl] = useState('');
  const [parameter, setParameter] = useState('');
  const [results, setResults] = useState<string[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const payloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '<svg onload=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'><script>alert('XSS')</script>",
    '<iframe src="javascript:alert(`XSS`)">',
    '<body onload=alert("XSS")>',
    '<input onfocus=alert("XSS") autofocus>',
  ];

  const testXSS = async () => {
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

          // Check if payload is reflected in response without proper encoding
          const decodedPayload = payload.toLowerCase();
          const lowerText = text.toLowerCase();

          if (lowerText.includes(decodedPayload) || lowerText.includes(payload.replace(/"/g, "'"))) {
            vulnerabilities.push(`Potential XSS with payload: ${payload.substring(0, 50)}...`);
          }
        } catch (err) {
          // Network error, continue
        }

        await new Promise((resolve) => setTimeout(resolve, 500));
      }

      if (vulnerabilities.length === 0) {
        vulnerabilities.push('No obvious XSS vulnerabilities detected');
      }

      setResults(vulnerabilities);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'XSS Detector',
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
          <span className={styles.toolIcon}>⚡</span>
          XSS Detector
        </h2>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.requestSection}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Target URL</label>
            <input
              type="text"
              className={styles.input}
              placeholder="https://example.com/search.php"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </div>

          <div className={styles.inputGroup}>
            <label className={styles.label}>Parameter Name</label>
            <input
              type="text"
              className={styles.input}
              placeholder="q"
              value={parameter}
              onChange={(e) => setParameter(e.target.value)}
            />
          </div>

          <button className={styles.sendButton} onClick={testXSS} disabled={loading}>
            {loading ? 'Testing...' : 'Test XSS'}
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
            <span>Testing XSS vectors...</span>
          </div>
        )}

        {results.length > 0 && (
          <div className={styles.results}>
            <h3 className={styles.sectionTitle}>Test Results</h3>
            {results.map((result, index) => (
              <div key={index} className={styles.resultItem}>
                <span style={{ color: result.includes('Potential') ? '#ff9800' : '#4caf50' }}>{result}</span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default XSSDetector;
