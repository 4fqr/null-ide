import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { LockIcon, LoadingIcon } from '../common/Icons';

const SessionMgmt: React.FC = () => {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [sessionToken, setSessionToken] = useState('');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testSession = async () => {
    if (!targetUrl.trim() || !sessionToken.trim()) {
      setError('Target URL and session token are required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ test: string; result: string }> = [];

      const entropy = calculateEntropy(sessionToken);
      found.push({
        test: 'Token Entropy',
        result:
          entropy > 100
            ? `Strong (${entropy.toFixed(2)} bits)`
            : `Weak (${entropy.toFixed(2)} bits)`,
      });

      try {
        const result1 = await window.electronAPI.net.httpFetch(targetUrl, {
          method: 'GET',
          headers: { Cookie: `session=${sessionToken}` },
          timeout: 5000,
        });

        await new Promise((resolve) => setTimeout(resolve, 1000));

        const result2 = await window.electronAPI.net.httpFetch(targetUrl, {
          method: 'GET',
          headers: { Cookie: `session=${sessionToken}` },
          timeout: 5000,
        });

        const sameSession = result1.status === result2.status;
        found.push({
          test: 'Session Fixation',
          result: sameSession ? 'Possibly Vulnerable' : 'Protected',
        });
      } catch {
        found.push({ test: 'Session Fixation', result: 'Error testing' });
      }

      const hasTokenInUrl = targetUrl.includes('session=') || targetUrl.includes('token=');
      found.push({
        test: 'Token in URL',
        result: hasTokenInUrl ? 'VULNERABLE!' : 'Safe',
      });

      const isNumeric = /^\d+$/.test(sessionToken);
      const isSequential = checkSequential(sessionToken);
      found.push({
        test: 'Token Predictability',
        result: isNumeric || isSequential ? 'VULNERABLE!' : 'Appears Random',
      });

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Session Management',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Session test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const calculateEntropy = (str: string): number => {
    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    for (const count of Object.values(freq)) {
      const p = count / str.length;
      entropy -= p * Math.log2(p);
    }
    return entropy * str.length;
  };

  const checkSequential = (str: string): boolean => {
    for (let i = 0; i < str.length - 2; i++) {
      if (
        str.charCodeAt(i + 1) === str.charCodeAt(i) + 1 &&
        str.charCodeAt(i + 2) === str.charCodeAt(i) + 2
      ) {
        return true;
      }
    }
    return false;
  };

  return (
    <ToolWrapper
      title="Session Management Tester"
      icon={<LockIcon />}
      description="Test session tokens for security vulnerabilities"
    >
      <div className={styles.inputGroup}>
        <label className={styles.label}>Target URL</label>
        <input
          type="text"
          className={styles.input}
          placeholder="https://example.com/api/profile"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
        />
      </div>

      <div className={styles.inputGroup}>
        <label className={styles.label}>Session Token</label>
        <input
          type="text"
          className={styles.input}
          placeholder="your-session-token"
          value={sessionToken}
          onChange={(e) => setSessionToken(e.target.value)}
        />
      </div>

      <div className={styles.buttonGroup}>
        <button className={styles.primaryBtn} onClick={testSession} disabled={loading}>
          {loading ? (
            <>
              <LoadingIcon /> Testing...
            </>
          ) : (
            'Test Session'
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
          <span>Testing session management...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Session Security Tests</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div className={styles.resultRow}>
                <span className={styles.resultLabel}>{result.test}</span>
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

export default SessionMgmt;
