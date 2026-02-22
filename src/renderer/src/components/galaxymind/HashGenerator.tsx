import { useState } from 'react';
import { LockIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

export default function HashGenerator() {
  const [input, setInput] = useState('');
  const [hashes, setHashes] = useState<Record<string, string>>({});
  const [error, setError] = useState('');

  const generateHashes = async () => {
    setError('');
    setHashes({});

    if (!input.trim()) {
      setError('Please enter text to hash');
      return;
    }

    try {
      const encoder = new TextEncoder();
      const data = encoder.encode(input);
      const results: Record<string, string> = {};

      const sha256 = await crypto.subtle.digest('SHA-256', data);
      results['SHA-256'] = bufferToHex(sha256);

      const sha384 = await crypto.subtle.digest('SHA-384', data);
      results['SHA-384'] = bufferToHex(sha384);

      const sha512 = await crypto.subtle.digest('SHA-512', data);
      results['SHA-512'] = bufferToHex(sha512);

      const sha1 = await crypto.subtle.digest('SHA-1', data);
      results['SHA-1'] = bufferToHex(sha1);

      setHashes(results);
    } catch {
      setError('Failed to generate hashes');
    }
  };

  const bufferToHex = (buffer: ArrayBuffer): string => {
    return Array.from(new Uint8Array(buffer))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  return (
    <ToolWrapper
      title="Hash Generator"
      icon={<LockIcon />}
      description="Generate cryptographic hashes for text input"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Input Text</label>
          <textarea
            className={styles.textarea}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Enter text to hash..."
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={generateHashes}>
            Generate Hashes
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setInput('');
              setHashes({});
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {Object.keys(hashes).length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Generated Hashes</span>
          </div>
          {Object.entries(hashes).map(([algo, hash]) => (
            <div key={algo} className={styles.resultItem}>
              <div
                className={styles.flexRow}
                style={{ justifyContent: 'space-between', marginBottom: 8 }}
              >
                <strong style={{ color: 'var(--color-accent)' }}>{algo}</strong>
                <button className={styles.copyBtn} onClick={() => copyToClipboard(hash)}>
                  Copy
                </button>
              </div>
              <div className={styles.resultContent}>{hash}</div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
