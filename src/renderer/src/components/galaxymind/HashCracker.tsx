import { useState } from 'react';
import styles from './Tool.module.css';

type HashType = 'md5' | 'sha1' | 'sha256' | 'sha512';
type AttackMode = 'dictionary' | 'brute-force';

export default function HashCracker() {
  const [hash, setHash] = useState('');
  const [hashType, setHashType] = useState<HashType>('md5');
  const [attackMode, setAttackMode] = useState<AttackMode>('dictionary');
  const [wordlist, setWordlist] = useState('');
  const [charset, setCharset] = useState('abcdefghijklmnopqrstuvwxyz0123456789');
  const [maxLength, setMaxLength] = useState(4);
  const [result, setResult] = useState('');
  const [progress, setProgress] = useState('');
  const [cracking, setCracking] = useState(false);

  const hashString = async (str: string, type: HashType): Promise<string> => {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    let hashBuffer: ArrayBuffer;

    switch (type) {
      case 'md5':
        // MD5 not available in Web Crypto, simulate with SHA-256 for demo
        hashBuffer = await crypto.subtle.digest('SHA-256', data);
        break;
      case 'sha1':
        hashBuffer = await crypto.subtle.digest('SHA-1', data);
        break;
      case 'sha256':
        hashBuffer = await crypto.subtle.digest('SHA-256', data);
        break;
      case 'sha512':
        hashBuffer = await crypto.subtle.digest('SHA-512', data);
        break;
    }

    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  };

  const crackDictionary = async () => {
    if (!hash.trim() || !wordlist.trim()) {
      alert('Please enter hash and wordlist');
      return;
    }

    setCracking(true);
    setResult('');
    setProgress('Starting dictionary attack...');

    const words = wordlist.split('\n').filter(w => w.trim());
    const targetHash = hash.toLowerCase().trim();

    for (let i = 0; i < words.length; i++) {
      const word = words[i].trim();
      const hashedWord = await hashString(word, hashType);

      if (i % 100 === 0) {
        setProgress(`Tested ${i}/${words.length} words...`);
        await new Promise(resolve => setTimeout(resolve, 0)); // Allow UI update
      }

      if (hashedWord === targetHash) {
        setResult(`✓ Hash cracked! Password: ${word}`);
        setProgress(`Found match after ${i + 1} attempts`);
        setCracking(false);
        return;
      }
    }

    setResult('✗ Hash not found in wordlist');
    setProgress(`Tested all ${words.length} words`);
    setCracking(false);
  };

  const crackBruteForce = async () => {
    if (!hash.trim() || !charset.trim()) {
      alert('Please enter hash and charset');
      return;
    }

    setCracking(true);
    setResult('');
    setProgress('Starting brute force attack...');

    const targetHash = hash.toLowerCase().trim();
    let attempts = 0;

    // Generator function for combinations
    function* generateCombinations(chars: string, length: number): Generator<string> {
      if (length === 0) {
        yield '';
        return;
      }
      for (const char of chars) {
        for (const rest of generateCombinations(chars, length - 1)) {
          yield char + rest;
        }
      }
    }

    for (let len = 1; len <= maxLength; len++) {
      setProgress(`Trying length ${len}...`);
      
      for (const combination of generateCombinations(charset, len)) {
        attempts++;
        const hashedCombination = await hashString(combination, hashType);

        if (attempts % 1000 === 0) {
          setProgress(`Tested ${attempts} combinations (length ${len})...`);
          await new Promise(resolve => setTimeout(resolve, 0)); // Allow UI update
        }

        if (hashedCombination === targetHash) {
          setResult(`✓ Hash cracked! Password: ${combination}`);
          setProgress(`Found match after ${attempts} attempts`);
          setCracking(false);
          return;
        }

        // Limit to prevent browser freeze (max 10k attempts in demo)
        if (attempts >= 10000) {
          setResult('✗ Stopped after 10,000 attempts (demo limit)');
          setProgress('Use dedicated tools for real cracking');
          setCracking(false);
          return;
        }
      }
    }

    setResult('✗ Hash not cracked within length limit');
    setProgress(`Tested ${attempts} combinations`);
    setCracking(false);
  };

  const startCracking = () => {
    if (attackMode === 'dictionary') {
      crackDictionary();
    } else {
      crackBruteForce();
    }
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔨</span>
          Hash Cracker
        </div>
        <div className={styles.toolSubtitle}>
          Crack password hashes using dictionary or brute force attacks
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label>Hash Type</label>
          <select
            value={hashType}
            onChange={(e) => setHashType(e.target.value as HashType)}
            disabled={cracking}
          >
            <option value="md5">MD5 (demo: SHA-256)</option>
            <option value="sha1">SHA-1</option>
            <option value="sha256">SHA-256</option>
            <option value="sha512">SHA-512</option>
          </select>
        </div>

        <div className={styles.inputGroup}>
          <label>Target Hash</label>
          <input
            type="text"
            value={hash}
            onChange={(e) => setHash(e.target.value)}
            placeholder="Enter hash to crack"
            disabled={cracking}
          />
        </div>

        <div className={styles.inputGroup}>
          <label>Attack Mode</label>
          <select
            value={attackMode}
            onChange={(e) => setAttackMode(e.target.value as AttackMode)}
            disabled={cracking}
          >
            <option value="dictionary">Dictionary Attack</option>
            <option value="brute-force">Brute Force</option>
          </select>
        </div>

        {attackMode === 'dictionary' ? (
          <div className={styles.inputGroup}>
            <label>Wordlist (one per line)</label>
            <textarea
              value={wordlist}
              onChange={(e) => setWordlist(e.target.value)}
              placeholder="password&#10;admin&#10;123456&#10;..."
              disabled={cracking}
            />
          </div>
        ) : (
          <>
            <div className={styles.inputGroup}>
              <label>Character Set</label>
              <input
                type="text"
                value={charset}
                onChange={(e) => setCharset(e.target.value)}
                placeholder="abcdefghijklmnopqrstuvwxyz0123456789"
                disabled={cracking}
              />
            </div>
            <div className={styles.inputGroup}>
              <label>Max Length</label>
              <input
                type="number"
                value={maxLength}
                onChange={(e) => setMaxLength(parseInt(e.target.value))}
                min="1"
                max="6"
                disabled={cracking}
              />
            </div>
          </>
        )}

        <button
          className={styles.primaryBtn}
          onClick={startCracking}
          disabled={cracking}
        >
          {cracking ? 'Cracking...' : 'Start Cracking'}
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
          <h3>Cracking Techniques</h3>
          <ul>
            <li><strong>Dictionary:</strong> Tests common passwords from a wordlist</li>
            <li><strong>Brute Force:</strong> Tests all possible combinations up to max length</li>
          </ul>
          <p className={styles.warning}>
            ⚠️ This is a demo implementation. For real cracking, use tools like Hashcat or John the Ripper with GPU acceleration.
          </p>
        </div>
      </div>
    </div>
  );
}
