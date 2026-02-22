import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { HashIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

type HashType = 'md5' | 'sha1' | 'sha256' | 'sha512';

export default function HashCracker() {
  const [hash, setHash] = useState('');
  const [hashType, setHashType] = useState<HashType>('md5');
  const [wordlist, setWordlist] = useState('');
  const [result, setResult] = useState('');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [error, setError] = useState('');

  const crack = async () => {
    if (!hash.trim()) {
      setError('Please enter a hash to crack');
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

    const words = wordlist.split('\n').filter((w) => w.trim());
    const targetHash = hash.toLowerCase().trim();

    for (let i = 0; i < words.length; i++) {
      const word = words[i].trim();
      setProgress(Math.round((i / words.length) * 100));

      try {
        const hashedResult = await window.electronAPI.crypto.hash(hashType, word);
        if (hashedResult && hashedResult.hash && hashedResult.hash.toLowerCase() === targetHash) {
          setResult(`Password found: ${word}`);
          setLoading(false);
          return;
        }
      } catch {}

      if (i % 50 === 0) await new Promise((r) => setTimeout(r, 0));
    }

    setResult('Password not found in wordlist');
    setLoading(false);
  };

  const identifyHashType = (h: string): string[] => {
    const types: string[] = [];
    if (h.length === 32) types.push('md5');
    if (h.length === 40) types.push('sha1');
    if (h.length === 64) types.push('sha256');
    if (h.length === 128) types.push('sha512');
    return types;
  };

  const detectedTypes = identifyHashType(hash);

  return (
    <ToolWrapper
      title="Hash Cracker"
      icon={<HashIcon />}
      description="Crack password hashes using dictionary attacks"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target Hash</label>
          <input
            type="text"
            className={styles.input}
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            placeholder="Enter hash to crack..."
            style={{ fontFamily: 'monospace' }}
          />
          {detectedTypes.length > 0 && (
            <small style={{ color: 'var(--color-text-tertiary)', marginTop: '4px' }}>
              Detected: {detectedTypes.join(', ')}
            </small>
          )}
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Hash Type</label>
          <select
            className={styles.select}
            value={hashType}
            onChange={(e) => setHashType(e.target.value as HashType)}
            disabled={loading}
          >
            <option value="md5">MD5</option>
            <option value="sha1">SHA-1</option>
            <option value="sha256">SHA-256</option>
            <option value="sha512">SHA-512</option>
          </select>
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Wordlist (one per line)</label>
          <textarea
            className={styles.textarea}
            value={wordlist}
            onChange={(e) => setWordlist(e.target.value)}
            placeholder="password&#10;admin&#10;123456"
            disabled={loading}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={crack} disabled={loading}>
            {loading ? `Cracking... ${progress}%` : 'Start Cracking'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setHash('');
              setWordlist('');
              setResult('');
              setError('');
              setProgress(0);
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
        <h3>Hash Cracking Tips</h3>
        <ul>
          <li>Dictionary attacks work against weak passwords</li>
          <li>Use longer wordlists for better results</li>
          <li>For production, use Hashcat or John the Ripper</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
