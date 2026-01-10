import { useState } from 'react';
import styles from './Tool.module.css';

export default function JWTCracker() {
  const [jwt, setJwt] = useState('');
  const [wordlist, setWordlist] = useState('');
  const [result, setResult] = useState('');
  const [progress, setProgress] = useState('');
  const [cracking, setCracking] = useState(false);
  const [decoded, setDecoded] = useState<{ header: any; payload: any } | null>(null);

  const decodeJWT = (token: string) => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        throw new Error('Invalid JWT format');
      }

      const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')));
      const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));

      setDecoded({ header, payload });
    } catch (error) {
      alert('Failed to decode JWT: Invalid format');
      setDecoded(null);
    }
  };

  const base64UrlEncode = (str: string): string => {
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };

  const hmacSha256 = async (secret: string, message: string): Promise<string> => {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(secret);
    const messageData = encoder.encode(message);

    const key = await crypto.subtle.importKey(
      'raw',
      keyData,
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );

    const signature = await crypto.subtle.sign('HMAC', key, messageData);
    const hashArray = Array.from(new Uint8Array(signature));
    const base64 = btoa(String.fromCharCode(...hashArray));
    
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  const crackJWT = async () => {
    if (!jwt.trim() || !wordlist.trim()) {
      alert('Please enter JWT token and wordlist');
      return;
    }

    setCracking(true);
    setResult('');
    setProgress('Starting JWT cracking...');

    const parts = jwt.split('.');
    if (parts.length !== 3) {
      alert('Invalid JWT format');
      setCracking(false);
      return;
    }

    const header = parts[0];
    const payload = parts[1];
    const targetSignature = parts[2];
    const message = `${header}.${payload}`;

    const secrets = wordlist.split('\n').filter(s => s.trim());

    for (let i = 0; i < secrets.length; i++) {
      const secret = secrets[i].trim();
      
      if (i % 100 === 0) {
        setProgress(`Tested ${i}/${secrets.length} secrets...`);
        await new Promise(resolve => setTimeout(resolve, 0));
      }

      try {
        const signature = await hmacSha256(secret, message);
        
        if (signature === targetSignature) {
          setResult(`✓ JWT Secret Found: ${secret}`);
          setProgress(`Cracked after ${i + 1} attempts`);
          setCracking(false);
          return;
        }
      } catch (error) {
        continue;
      }
    }

    setResult('✗ Secret not found in wordlist');
    setProgress(`Tested all ${secrets.length} secrets`);
    setCracking(false);
  };

  const analyzeJWT = () => {
    if (!jwt.trim()) {
      alert('Please enter a JWT token');
      return;
    }
    decodeJWT(jwt);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔑</span>
          JWT Cracker
        </div>
        <div className={styles.toolSubtitle}>
          Crack weak JWT secrets using dictionary attacks
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label>JWT Token</label>
          <textarea
            value={jwt}
            onChange={(e) => setJwt(e.target.value)}
            placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
            disabled={cracking}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.secondaryBtn} onClick={analyzeJWT} disabled={cracking}>
            Analyze JWT
          </button>
        </div>

        {decoded && (
          <div className={styles.outputSection}>
            <label>Decoded JWT</label>
            <div className={styles.output}>
              <strong>Header:</strong>
              <br />
              {JSON.stringify(decoded.header, null, 2)}
              <br /><br />
              <strong>Payload:</strong>
              <br />
              {JSON.stringify(decoded.payload, null, 2)}
            </div>
          </div>
        )}

        <div className={styles.inputGroup}>
          <label>Secret Wordlist (one per line)</label>
          <textarea
            value={wordlist}
            onChange={(e) => setWordlist(e.target.value)}
            placeholder="secret&#10;password&#10;admin123&#10;..."
            disabled={cracking}
          />
        </div>

        <button
          className={styles.primaryBtn}
          onClick={crackJWT}
          disabled={cracking}
        >
          {cracking ? 'Cracking...' : 'Crack Secret'}
        </button>

        {progress && (
          <div className={styles.outputSection}>
            <label>Progress</label>
            <div className={styles.output}>{progress}</div>
          </div>
        )}

        {result && (
          <div className={styles.outputSection}>
            <label>Result</label>
            <div className={styles.output}>{result}</div>
          </div>
        )}

        <div className={styles.infoBox}>
          <h3>JWT Security</h3>
          <ul>
            <li>Weak secrets can be cracked using dictionary attacks</li>
            <li>Common secrets: "secret", "password", company names, etc.</li>
            <li>Once cracked, attackers can forge tokens with any claims</li>
            <li>Use strong, random secrets (32+ characters) in production</li>
          </ul>
          <p className={styles.warning}>
            ⚠️ Only crack JWTs you have authorization to test. This demo supports HS256 algorithm only.
          </p>
        </div>
      </div>
    </div>
  );
}
