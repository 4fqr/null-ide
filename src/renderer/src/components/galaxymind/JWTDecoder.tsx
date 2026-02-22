import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { TicketIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function JWTDecoder() {
  const [jwt, setJwt] = useState('');
  const [header, setHeader] = useState<Record<string, unknown> | null>(null);
  const [payload, setPayload] = useState<Record<string, unknown> | null>(null);
  const [signature, setSignature] = useState('');
  const [error, setError] = useState('');

  const decode = () => {
    setError('');
    setHeader(null);
    setPayload(null);
    setSignature('');

    if (!jwt.trim()) {
      setError('Please enter a JWT token');
      return;
    }

    const parts = jwt.trim().split('.');
    if (parts.length !== 3) {
      setError('Invalid JWT format - must have 3 parts');
      return;
    }

    try {
      const decodeB64 = (str: string) => atob(str.replace(/-/g, '+').replace(/_/g, '/'));
      setHeader(JSON.parse(decodeB64(parts[0])));
      setPayload(JSON.parse(decodeB64(parts[1])));
      setSignature(parts[2]);
    } catch {
      setError('Failed to decode JWT - invalid encoding');
    }
  };

  const getExpiryStatus = (): string => {
    if (!payload?.exp) return 'No expiration';
    const exp = (payload.exp as number) * 1000;
    const diff = exp - Date.now();
    if (diff < 0) return 'EXPIRED';
    if (diff < 3600000) return `Expires in ${Math.round(diff / 60000)} min`;
    if (diff < 86400000) return `Expires in ${Math.round(diff / 3600000)} hours`;
    return `Expires in ${Math.round(diff / 86400000)} days`;
  };

  return (
    <ToolWrapper
      title="JWT Decoder"
      icon={<TicketIcon />}
      description="Decode and inspect JWT tokens"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>JWT Token</label>
          <textarea
            className={styles.textarea}
            value={jwt}
            onChange={(e) => setJwt(e.target.value)}
            placeholder="Paste your JWT token here..."
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={decode}>
            Decode Token
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setJwt('');
              setHeader(null);
              setPayload(null);
              setSignature('');
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {header && payload && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Decoded JWT</span>
            <span style={{ color: 'var(--color-accent)', fontSize: '12px' }}>
              {getExpiryStatus()}
            </span>
          </div>

          <div className={styles.resultItem}>
            <div
              className={styles.flexRow}
              style={{ justifyContent: 'space-between', alignItems: 'center' }}
            >
              <strong style={{ color: 'var(--color-accent)' }}>Header</strong>
              <button
                className={styles.copyBtn}
                onClick={() => navigator.clipboard.writeText(JSON.stringify(header, null, 2))}
              >
                Copy
              </button>
            </div>
            <pre className={styles.codeBlock}>{JSON.stringify(header, null, 2)}</pre>
          </div>

          <div className={styles.resultItem}>
            <div
              className={styles.flexRow}
              style={{ justifyContent: 'space-between', alignItems: 'center' }}
            >
              <strong style={{ color: 'var(--color-accent)' }}>Payload</strong>
              <button
                className={styles.copyBtn}
                onClick={() => navigator.clipboard.writeText(JSON.stringify(payload, null, 2))}
              >
                Copy
              </button>
            </div>
            <pre className={styles.codeBlock}>{JSON.stringify(payload, null, 2)}</pre>
          </div>

          <div className={styles.resultItem}>
            <strong style={{ color: 'var(--color-accent)' }}>Signature</strong>
            <div className={styles.code}>{signature}</div>
          </div>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>JWT Structure</h3>
        <ul>
          <li>
            <strong>Header:</strong> Algorithm and token type
          </li>
          <li>
            <strong>Payload:</strong> Claims (user data, expiration, etc.)
          </li>
          <li>
            <strong>Signature:</strong> Verification of token integrity
          </li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
