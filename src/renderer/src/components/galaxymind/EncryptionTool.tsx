import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { LockIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

type Algorithm = 'AES-GCM' | 'AES-CBC';
type Mode = 'encrypt' | 'decrypt';

export default function EncryptionTool() {
  const [algorithm, setAlgorithm] = useState<Algorithm>('AES-GCM');
  const [mode, setMode] = useState<Mode>('encrypt');
  const [input, setInput] = useState('');
  const [password, setPassword] = useState('');
  const [output, setOutput] = useState('');
  const [iv, setIv] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const deriveKey = async (password: string): Promise<CryptoKey> => {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode('NullIDE-Salt'), iterations: 100000, hash: 'SHA-256' },
      keyMaterial,
      { name: algorithm.split('-')[0], length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  };

  const encrypt = async () => {
    if (!input.trim() || !password.trim()) {
      setError('Please enter data and password');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const enc = new TextEncoder();
      const key = await deriveKey(password);
      const ivArray =
        algorithm === 'AES-GCM'
          ? crypto.getRandomValues(new Uint8Array(12))
          : crypto.getRandomValues(new Uint8Array(16));

      const encrypted = await crypto.subtle.encrypt(
        { name: algorithm, iv: ivArray },
        key,
        enc.encode(input)
      );

      setIv(
        Array.from(ivArray)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')
      );
      setOutput(
        Array.from(new Uint8Array(encrypted))
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('')
      );
    } catch (err) {
      setError('Encryption failed: ' + (err as Error).message);
    }

    setLoading(false);
  };

  const decrypt = async () => {
    if (!input.trim() || !password.trim() || !iv.trim()) {
      setError('Please enter encrypted data, password, and IV');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const key = await deriveKey(password);
      const ivArray = new Uint8Array(iv.match(/.{1,2}/g)?.map((b) => parseInt(b, 16)) || []);
      const encryptedArray = new Uint8Array(
        input.match(/.{1,2}/g)?.map((b) => parseInt(b, 16)) || []
      );

      const decrypted = await crypto.subtle.decrypt(
        { name: algorithm, iv: ivArray },
        key,
        encryptedArray
      );
      setOutput(new TextDecoder().decode(decrypted));
    } catch (err) {
      setError('Decryption failed: ' + (err as Error).message);
    }

    setLoading(false);
  };

  const process = () => {
    if (mode === 'encrypt') encrypt();
    else decrypt();
  };

  return (
    <ToolWrapper
      title="Encryption Tool"
      icon={<LockIcon />}
      description="Encrypt and decrypt data using AES"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Algorithm</label>
          <select
            className={styles.select}
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value as Algorithm)}
          >
            <option value="AES-GCM">AES-256-GCM (Recommended)</option>
            <option value="AES-CBC">AES-256-CBC</option>
          </select>
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Mode</label>
          <div className={styles.flexRow}>
            <button
              className={mode === 'encrypt' ? styles.primaryBtn : styles.secondaryBtn}
              onClick={() => setMode('encrypt')}
              style={{ flex: 1 }}
            >
              Encrypt
            </button>
            <button
              className={mode === 'decrypt' ? styles.primaryBtn : styles.secondaryBtn}
              onClick={() => setMode('decrypt')}
              style={{ flex: 1 }}
            >
              Decrypt
            </button>
          </div>
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Password</label>
          <input
            type="password"
            className={styles.input}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password..."
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>
            {mode === 'encrypt' ? 'Plaintext' : 'Encrypted Data (Hex)'}
          </label>
          <textarea
            className={styles.textarea}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={
              mode === 'encrypt' ? 'Enter text to encrypt...' : 'Enter hex data to decrypt...'
            }
          />
        </div>
        {mode === 'decrypt' && (
          <div className={styles.inputGroup}>
            <label className={styles.label}>IV (Hex)</label>
            <input
              type="text"
              className={styles.input}
              value={iv}
              onChange={(e) => setIv(e.target.value)}
              placeholder="Enter IV in hex format..."
            />
          </div>
        )}
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={process} disabled={loading}>
            {loading ? 'Processing...' : mode === 'encrypt' ? 'Encrypt' : 'Decrypt'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setInput('');
              setOutput('');
              setIv('');
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {output && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>
              {mode === 'encrypt' ? 'Encrypted Data' : 'Decrypted Data'}
            </span>
            <button
              className={styles.copyBtn}
              onClick={() => navigator.clipboard.writeText(output)}
            >
              Copy
            </button>
          </div>
          <div className={styles.resultContent}>{output}</div>
        </div>
      )}

      {mode === 'encrypt' && iv && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>IV (Save this!)</span>
            <button className={styles.copyBtn} onClick={() => navigator.clipboard.writeText(iv)}>
              Copy
            </button>
          </div>
          <div className={styles.resultContent}>{iv}</div>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>Encryption Details</h3>
        <ul>
          <li>
            <strong>AES-256-GCM:</strong> Authenticated encryption (AEAD)
          </li>
          <li>
            <strong>AES-256-CBC:</strong> Cipher block chaining mode
          </li>
          <li>
            <strong>Key Derivation:</strong> PBKDF2 with 100,000 iterations
          </li>
          <li>Save the IV along with the ciphertext for decryption</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
