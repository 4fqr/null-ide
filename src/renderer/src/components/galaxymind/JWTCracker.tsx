import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { KeyIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function JWTCracker() {
  const [jwt, setJwt] = useState('');
  const [wordlist, setWordlist] = useState('');
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [decoded, setDecoded] = useState<{
    header: Record<string, unknown>;
    payload: Record<string, unknown>;
  } | null>(null);
  const [error, setError] = useState('');

  const decodeJWT = (token: string) => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      return {
        header: JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/'))),
        payload: JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/'))),
      };
    } catch {
      return null;
    }
  };

  const analyze = () => {
    setError('');
    if (!jwt.trim()) {
      setError('Please enter a JWT token');
      return;
    }
    const decoded = decodeJWT(jwt);
    if (decoded) {
      setDecoded(decoded);
    } else {
      setError('Invalid JWT format');
    }
  };

  const crack = async () => {
    if (!jwt.trim()) {
      setError('Please enter a JWT token');
      return;
    }
    if (!wordlist.trim()) {
      setError('Please enter a wordlist');
      return;
    }

    setLoading(true);
    setError('');
    setResult('');
    setProgress(0);

    const parts = jwt.split('.');
    if (parts.length !== 3) {
      setError('Invalid JWT format');
      setLoading(false);
      return;
    }

    const message = `${parts[0]}.${parts[1]}`;
    const targetSig = parts[2];
    const secrets = wordlist.split('\n').filter((s) => s.trim());

    for (let i = 0; i < secrets.length; i++) {
      const secret = secrets[i].trim();
      setProgress(Math.round((i / secrets.length) * 100));

      try {
        const encoder = new TextEncoder();
        const key = await crypto.subtle.importKey(
          'raw',
          encoder.encode(secret),
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign']
        );
        const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
        const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)))
          .replace(/\+/g, '-')
          .replace(/\//g, '_')
          .replace(/=/g, '');

        if (sigB64 === targetSig) {
          setResult(`Secret found: ${secret}`);
          setLoading(false);
          return;
        }
      } catch {}

      if (i % 50 === 0) await new Promise((r) => setTimeout(r, 0));
    }

    setResult('Secret not found in wordlist');
    setLoading(false);
  };

  return (
    <ToolWrapper
      title="JWT Cracker"
      icon={<KeyIcon />}
      description="Crack weak JWT secrets using dictionary attacks"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>JWT Token</label>
          <textarea
            className={styles.textarea}
            value={jwt}
            onChange={(e) => setJwt(e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            disabled={loading}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.secondaryBtn} onClick={analyze} disabled={loading}>
            Analyze
          </button>
        </div>
      </div>

      {decoded && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Decoded JWT</span>
          </div>
          <div className={styles.resultItem}>
            <strong style={{ color: 'var(--color-accent)' }}>Header</strong>
            <pre className={styles.codeBlock}>{JSON.stringify(decoded.header, null, 2)}</pre>
          </div>
          <div className={styles.resultItem}>
            <strong style={{ color: 'var(--color-accent)' }}>Payload</strong>
            <pre className={styles.codeBlock}>{JSON.stringify(decoded.payload, null, 2)}</pre>
          </div>
        </div>
      )}

      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Secret Wordlist</label>
          <textarea
            className={styles.textarea}
            value={wordlist}
            onChange={(e) => setWordlist(e.target.value)}
            placeholder="secret&#10;password&#10;admin"
            disabled={loading}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={crack} disabled={loading}>
            {loading ? `Cracking... ${progress}%` : 'Crack Secret'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setJwt('');
              setWordlist('');
              setResult('');
              setDecoded(null);
              setError('');
            }}
            disabled={loading}
          >
            Clear
          </button>
        </div>
      </div>

      {loading && (
        <div className={styles.resultBox}>
          <div className={styles.progressBar}>
            <div className={styles.progressFill} style={{ width: `${progress}%` }} />
          </div>
        </div>
      )}

      {error && <div className={styles.errorBox}>{error}</div>}

      {result && (
        <div className={result.includes('found') ? styles.successBox : styles.warningBox}>
          {result}
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>JWT Security</h3>
        <ul>
          <li>Weak secrets can be cracked using dictionary attacks</li>
          <li>Common secrets: "secret", "password", company names</li>
          <li>Use strong, random secrets (32+ characters)</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
