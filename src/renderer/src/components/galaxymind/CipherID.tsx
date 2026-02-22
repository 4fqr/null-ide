import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { LockIcon, LoadingIcon } from '../common/Icons';

interface CipherIdentification {
  possibleCiphers: Array<{
    name: string;
    confidence: number;
    characteristics: string[];
  }>;
  analysis: {
    length: number;
    characterSet: string;
    entropy: number;
    patterns: string[];
  };
}

export default function CipherID() {
  const { addToolResult } = useStore();
  const [ciphertext, setCiphertext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<CipherIdentification | null>(null);

  const identifyCipher = async () => {
    if (!ciphertext) return;

    setLoading(true);
    setResult(null);

    try {
      const possibleCiphers: Array<{
        name: string;
        confidence: number;
        characteristics: string[];
      }> = [];
      const patterns: string[] = [];

      const length = ciphertext.length;

      let characterSet = 'Unknown';
      const hasOnlyHex = /^[0-9a-fA-F]+$/.test(ciphertext);
      const hasOnlyBase64 = /^[A-Za-z0-9+/=]+$/.test(ciphertext);
      const hasOnlyAlpha = /^[A-Za-z]+$/.test(ciphertext);
      const hasOnlyDigits = /^[0-9]+$/.test(ciphertext);

      if (hasOnlyHex) characterSet = 'Hexadecimal';
      else if (hasOnlyBase64) characterSet = 'Base64';
      else if (hasOnlyAlpha) characterSet = 'Alphabetic';
      else if (hasOnlyDigits) characterSet = 'Numeric';
      else characterSet = 'Mixed';

      const freq: { [key: string]: number } = {};
      for (const char of ciphertext) {
        freq[char] = (freq[char] || 0) + 1;
      }
      let entropy = 0;
      for (const count of Object.values(freq)) {
        const p = count / length;
        entropy -= p * Math.log2(p);
      }

      if (ciphertext.endsWith('=') || ciphertext.endsWith('==')) {
        patterns.push('Base64 padding detected');
        possibleCiphers.push({
          name: 'Base64 Encoded Data',
          confidence: 95,
          characteristics: ['Padding with =', 'Base64 character set', 'Length multiple of 4'],
        });
      }

      if (hasOnlyHex && length % 32 === 0) {
        patterns.push('Hex string, length multiple of 32');
        possibleCiphers.push({
          name: 'AES-CBC/AES-ECB (hex)',
          confidence: 80,
          characteristics: ['Hexadecimal', '128-bit block alignment', 'Common AES output'],
        });
      }

      if (hasOnlyHex && length === 64) {
        patterns.push('64 hex characters - likely SHA-256');
        possibleCiphers.push({
          name: 'SHA-256 Hash',
          confidence: 90,
          characteristics: ['256 bits (64 hex chars)', 'High entropy', 'One-way hash'],
        });
      }

      if (hasOnlyHex && length === 40) {
        patterns.push('40 hex characters - likely SHA-1');
        possibleCiphers.push({
          name: 'SHA-1 Hash',
          confidence: 90,
          characteristics: ['160 bits (40 hex chars)', 'Deprecated hash', 'One-way hash'],
        });
      }

      if (hasOnlyHex && length === 32) {
        patterns.push('32 hex characters - likely MD5');
        possibleCiphers.push({
          name: 'MD5 Hash',
          confidence: 85,
          characteristics: ['128 bits (32 hex chars)', 'Weak hash', 'Common in legacy systems'],
        });
      }

      if (
        length === 36 &&
        ciphertext.match(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i)
      ) {
        patterns.push('UUID/GUID format detected');
        possibleCiphers.push({
          name: 'UUID/GUID',
          confidence: 100,
          characteristics: ['Standard UUID format', 'Not encrypted', 'Unique identifier'],
        });
      }

      if (hasOnlyAlpha && entropy < 4.0) {
        patterns.push('Low entropy alphabetic text');
        possibleCiphers.push({
          name: 'Classical Cipher (Caesar/Vigenere)',
          confidence: 70,
          characteristics: ['Low entropy', 'Alphabetic only', 'Substitution cipher likely'],
        });
      }

      if (
        ciphertext.startsWith('$2') ||
        ciphertext.startsWith('$2a$') ||
        ciphertext.startsWith('$2b$')
      ) {
        patterns.push('Bcrypt format detected');
        possibleCiphers.push({
          name: 'Bcrypt Hash',
          confidence: 100,
          characteristics: ['Bcrypt prefix', 'Password hashing', 'Includes cost factor'],
        });
      }

      if (ciphertext.includes('.') && ciphertext.split('.').length === 3) {
        patterns.push('Three-part dot-separated format');
        possibleCiphers.push({
          name: 'JWT (JSON Web Token)',
          confidence: 85,
          characteristics: [
            'Header.Payload.Signature format',
            'Base64url encoded',
            'Contains JSON',
          ],
        });
      }

      if (entropy > 7.5 && hasOnlyBase64) {
        patterns.push('High entropy Base64 - likely encrypted');
        possibleCiphers.push({
          name: 'Encrypted Data (AES/RSA)',
          confidence: 75,
          characteristics: ['High entropy', 'Base64 encoding', 'Strong encryption likely'],
        });
      }

      if (possibleCiphers.length === 0) {
        possibleCiphers.push({
          name: 'Unknown/Custom Encoding',
          confidence: 50,
          characteristics: [
            'Unable to identify specific cipher',
            'May be custom encoding',
            'Further analysis needed',
          ],
        });
      }

      possibleCiphers.sort((a, b) => b.confidence - a.confidence);

      const identification: CipherIdentification = {
        possibleCiphers,
        analysis: {
          length,
          characterSet,
          entropy: Math.round(entropy * 100) / 100,
          patterns,
        },
      };

      setResult(identification);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Cipher ID',
        output: identification,
        input: { ciphertext },
        timestamp: Date.now(),
        success: true,
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setResult({
        possibleCiphers: [],
        analysis: {
          length: 0,
          characterSet: 'Error',
          entropy: 0,
          patterns: [`Error: ${errorMsg}`],
        },
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Cipher Identification Tool"
      icon={<LockIcon />}
      description="Identify encryption, hashing, or encoding used in ciphertext"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Ciphertext / Hash / Encoded Data</label>
          <textarea
            value={ciphertext}
            onChange={(e) => setCiphertext(e.target.value)}
            placeholder="Paste encrypted or encoded text here..."
            className={styles.textarea}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={identifyCipher}
            disabled={loading || !ciphertext}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Analyzing...
              </>
            ) : (
              'Identify Cipher'
            )}
          </button>
        </div>
      </div>

      {result && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Identification Results</span>
          </div>

          <div className={styles.resultItem}>
            <strong>Analysis:</strong>
            <div style={{ marginTop: '8px' }}>
              <span className={styles.tag}>Length: {result.analysis.length}</span>
              <span className={styles.tag}>Charset: {result.analysis.characterSet}</span>
              <span className={styles.tag}>Entropy: {result.analysis.entropy} bits/char</span>
            </div>
          </div>

          {result.analysis.patterns.length > 0 && (
            <div className={styles.resultItem}>
              <strong>Detected Patterns:</strong>
              <ul style={{ margin: '8px 0 0 20px', color: 'var(--color-text-secondary)' }}>
                {result.analysis.patterns.map((pattern, idx) => (
                  <li key={idx}>{pattern}</li>
                ))}
              </ul>
            </div>
          )}

          <div className={styles.resultItem}>
            <strong>Possible Ciphers (by confidence):</strong>
            {result.possibleCiphers.map((cipher, idx) => (
              <div
                key={idx}
                style={{
                  marginTop: '10px',
                  padding: '10px',
                  background: 'var(--color-bg-tertiary)',
                  borderRadius: 'var(--border-radius-sm)',
                }}
              >
                <div>
                  <strong>{cipher.name}</strong>
                  <span
                    className={
                      cipher.confidence >= 90
                        ? styles.badgeSuccess
                        : cipher.confidence >= 70
                          ? styles.badgeInfo
                          : styles.badgeWarning
                    }
                    style={{ marginLeft: '8px' }}
                  >
                    {cipher.confidence}% confidence
                  </span>
                </div>
                <ul
                  style={{
                    margin: '8px 0 0 20px',
                    color: 'var(--color-text-tertiary)',
                    fontSize: '12px',
                  }}
                >
                  {cipher.characteristics.map((char, charIdx) => (
                    <li key={charIdx}>{char}</li>
                  ))}
                </ul>
              </div>
            ))}
          </div>
        </div>
      )}
    </ToolWrapper>
  );
}
