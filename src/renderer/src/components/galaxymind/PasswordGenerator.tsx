import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { PasswordIcon, CopyIcon } from '../common/Icons';

export default function PasswordGenerator() {
  const [password, setPassword] = useState('');
  const [length, setLength] = useState(16);
  const [options, setOptions] = useState({
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
  });

  const generatePassword = () => {
    let charset = '';
    if (options.lowercase) charset += 'abcdefghijklmnopqrstuvwxyz';
    if (options.uppercase) charset += 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
    if (options.numbers) charset += '0123456789';
    if (options.symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?';

    if (!charset) {
      setPassword('Please select at least one option');
      return;
    }

    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    const generated = Array.from(array)
      .map((x) => charset[x % charset.length])
      .join('');
    setPassword(generated);
  };

  const handleCopy = () => {
    if (password) {
      navigator.clipboard.writeText(password);
    }
  };

  return (
    <ToolWrapper
      title="Password Generator"
      icon={<PasswordIcon />}
      description="Generate secure random passwords with customizable options"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Password Length: {length}</label>
          <input
            type="range"
            min="8"
            max="64"
            value={length}
            onChange={(e) => setLength(parseInt(e.target.value))}
            style={{ width: '100%' }}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Options</label>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {[
              { key: 'uppercase', label: 'Uppercase (A-Z)' },
              { key: 'lowercase', label: 'Lowercase (a-z)' },
              { key: 'numbers', label: 'Numbers (0-9)' },
              { key: 'symbols', label: 'Symbols (!@#$...)' },
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
            Generate Password
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
            <pre style={{ margin: 0, fontSize: '1.2rem', userSelect: 'all' }}>{password}</pre>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
}
