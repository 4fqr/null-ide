import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { LockIcon, LoadingIcon } from '../common/Icons';

const JWTWeakSecret: React.FC = () => {
  const { addToolResult } = useStore();
  const [jwt, setJwt] = useState('');
  const [results, setResults] = useState<Array<{ attack: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const commonSecrets = [
    'secret',
    'password',
    '123456',
    'admin',
    'test',
    'default',
    'changeme',
    'qwerty',
    'letmein',
    'welcome',
    'monkey',
    '1234',
  ];

  const testJWT = async () => {
    if (!jwt.trim()) {
      setError('JWT token is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ attack: string; result: string }> = [];

      const parts = jwt.split('.');
      if (parts.length !== 3) {
        setError('Invalid JWT format');
        setLoading(false);
        return;
      }

      const header = JSON.parse(atob(parts[0]));
      const payload = JSON.parse(atob(parts[1]));
      const signature = parts[2];

      found.push({
        attack: 'Algorithm',
        result: header.alg || 'None specified',
      });

      if (header.alg === 'none' || header.alg === 'None') {
        found.push({
          attack: 'None Algorithm',
          result: 'VULNERABLE!',
        });
      }

      for (const secret of commonSecrets) {
        try {
          const hashResult = await window.electronAPI.crypto.hash(
            'sha256',
            `${parts[0]}.${parts[1]}${secret}`
          );
          const computedSig = (hashResult.hash || '').substring(0, signature.length);

          if (computedSig === signature) {
            found.push({
              attack: 'Weak Secret Found',
              result: `VULNERABLE! Secret: ${secret}`,
            });
            break;
          }
        } catch {
          void 0;
        }
      }

      if (payload.exp) {
        const expired = Date.now() / 1000 > payload.exp;
        found.push({
          attack: 'Token Expiration',
          result: expired ? 'Expired' : 'Valid',
        });
      } else {
        found.push({
          attack: 'Token Expiration',
          result: 'No exp claim (never expires)',
        });
      }

      if (header.kid) {
        found.push({
          attack: 'kid Header',
          result: `Present: ${header.kid} (test for path traversal)`,
        });
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'JWT Weak Secret',
        timestamp: Date.now(),
        input: { jwt: `${jwt.substring(0, 20)}...` },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'JWT test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="JWT Weak Secret Cracker"
      icon={<LockIcon />}
      description="Test JWT tokens for weak secrets and common vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>JWT Token</label>
          <input
            type="text"
            className={styles.input}
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            value={jwt}
            onChange={(e) => setJwt(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testJWT} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test JWT'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing JWT security...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>JWT Security Analysis</span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span className={styles.textSuccess}>{result.attack}</span>
              <span
                className={
                  styles.ml8 + ' ' + (result.result.includes('VULNERABLE') ? styles.textError : '')
                }
                style={{
                  fontSize: '11px',
                  color: result.result.includes('VULNERABLE') ? undefined : '#888',
                }}
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

export default JWTWeakSecret;
