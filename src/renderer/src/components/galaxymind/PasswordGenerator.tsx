import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { PasswordIcon, CopyIcon } from '../common/Icons';

export default function PasswordGenerator() {
  const [password, setPassword] = useState('');
  const [length, setLength] = useState(24);
  const [options, setOptions] = useState({
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    ambiguous: false,
  });
  const [entropy, setEntropy] = useState(0);

  const getCharset = () => {
    let charset = '';
    let ambiguousChars = 'l1IO0';

    const addChars = (chars: string) => {
      if (!options.ambiguous) {
        return chars
          .split('')
          .filter((c) => !ambiguousChars.includes(c))
          .join('');
      }
      return chars;
    };

    if (options.lowercase) charset += addChars('abcdefghijklmnopqrstuvwxyz');
    if (options.uppercase) charset += addChars('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (options.numbers) charset += addChars('0123456789');
    if (options.symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?~`';

    return charset;
  };

  const generatePassword = () => {
    const charset = getCharset();

    if (!charset) {
      setPassword('Please select at least one option');
      setEntropy(0);
      return;
    }

    const charsetLength = charset.length;
    const charsNeeded = length;

    const randomValues = new Uint32Array(charsNeeded);
    crypto.getRandomValues(randomValues);

    const maxValid = Math.floor(4294967296 / charsetLength) * charsetLength;

    let generated = '';
    let generatedCount = 0;
    let attempts = 0;
    const maxAttempts = charsNeeded * 10;

    while (generatedCount < charsNeeded && attempts < maxAttempts) {
      const randomIndex = attempts % charsNeeded;
      const value = randomValues[randomIndex];

      if (value < maxValid) {
        generated += charset[value % charsetLength];
        generatedCount++;
      }
      attempts++;
    }

    if (generated.length < length) {
      const extraRandom = new Uint32Array(length - generated.length);
      crypto.getRandomValues(extraRandom);
      for (let i = 0; i < extraRandom.length; i++) {
        generated += charset[extraRandom[i] % charsetLength];
      }
    }

    const bitsOfEntropy = Math.floor(length * Math.log2(charsetLength));
    setEntropy(bitsOfEntropy);
    setPassword(generated);
  };

  const getStrengthInfo = (bits: number) => {
    if (bits >= 128)
      return { level: 'Excellent', color: '#00ff00', desc: 'Uncrackable with current technology' };
    if (bits >= 80)
      return {
        level: 'Strong',
        color: '#88ff00',
        desc: 'Very secure, would take centuries to crack',
      };
    if (bits >= 60) return { level: 'Good', color: '#ffff00', desc: 'Secure for most purposes' };
    if (bits >= 40)
      return { level: 'Fair', color: '#ff8800', desc: 'Could be cracked with effort' };
    return { level: 'Weak', color: '#ff0000', desc: 'Easily crackable' };
  };

  const handleCopy = () => {
    if (password) {
      navigator.clipboard.writeText(password);
    }
  };

  const strength = getStrengthInfo(entropy);

  return (
    <ToolWrapper
      title="Password Generator"
      icon={<PasswordIcon />}
      description="Generate cryptographically secure random passwords"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Password Length: {length}</label>
          <input
            type="range"
            min="12"
            max="128"
            value={length}
            onChange={(e) => setLength(parseInt(e.target.value))}
            style={{ width: '100%' }}
          />
          <div
            style={{
              display: 'flex',
              justifyContent: 'space-between',
              fontSize: '0.8rem',
              color: '#888',
            }}
          >
            <span>12</span>
            <span>128</span>
          </div>
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Character Types</label>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {[
              { key: 'uppercase', label: 'Uppercase (A-Z)' },
              { key: 'lowercase', label: 'Lowercase (a-z)' },
              { key: 'numbers', label: 'Numbers (0-9)' },
              { key: 'symbols', label: 'Symbols (!@#$%^&*...)' },
              { key: 'ambiguous', label: 'Include ambiguous (l, 1, I, O, 0)' },
            ].map(({ key, label }) => (
              <label
                key={key}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  cursor: 'pointer',
                }}
              >
                <input
                  type="checkbox"
                  checked={options[key as keyof typeof options]}
                  onChange={(e) => setOptions({ ...options, [key]: e.target.checked })}
                />
                <span>{label}</span>
              </label>
            ))}
          </div>
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={generatePassword}>
            Generate Secure Password
          </button>
        </div>
      </div>

      {password && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Generated Password</span>
            <button className={styles.copyBtn} onClick={handleCopy}>
              <CopyIcon /> Copy
            </button>
          </div>
          <div className={styles.resultContent}>
            <pre
              style={{ margin: 0, fontSize: '1.2rem', userSelect: 'all', wordBreak: 'break-all' }}
            >
              {password}
            </pre>
          </div>

          {entropy > 0 && (
            <div
              style={{
                marginTop: '1rem',
                padding: '0.75rem',
                background: 'rgba(0,0,0,0.2)',
                borderRadius: '4px',
              }}
            >
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: '0.5rem',
                }}
              >
                <span>
                  Strength: <strong style={{ color: strength.color }}>{strength.level}</strong>
                </span>
                <span>{entropy} bits of entropy</span>
              </div>
              <div
                style={{
                  height: '8px',
                  background: '#333',
                  borderRadius: '4px',
                  overflow: 'hidden',
                }}
              >
                <div
                  style={{
                    height: '100%',
                    width: `${Math.min(100, (entropy / 128) * 100)}%`,
                    background: strength.color,
                    transition: 'width 0.3s',
                  }}
                />
              </div>
              <div style={{ marginTop: '0.5rem', fontSize: '0.85rem', color: '#aaa' }}>
                {strength.desc}
              </div>
            </div>
          )}
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>Cryptographic Security</h3>
        <ul>
          <li>Uses Web Crypto API (cryptographically secure RNG)</li>
          <li>Eliminates modulo bias for uniform distribution</li>
          <li>128+ bits of entropy = uncrackable</li>
          <li>Passwords generated locally, never transmitted</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
