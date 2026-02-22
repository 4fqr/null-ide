import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { LockIcon, LoadingIcon } from '../common/Icons';

const PasswordPolicyChecker: React.FC = () => {
  const { addToolResult } = useStore();
  const [password, setPassword] = useState('');
  const [results, setResults] = useState<Array<{ check: string; passed: boolean; detail: string }>>(
    []
  );
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const checkPassword = () => {
    if (!password.trim()) {
      setError('Password is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const checks: Array<{ check: string; passed: boolean; detail: string }> = [];

      const length = password.length;
      checks.push({
        check: 'Length',
        passed: length >= 12,
        detail: `${length} characters (minimum 12 recommended)`,
      });

      const hasUppercase = /[A-Z]/.test(password);
      checks.push({
        check: 'Uppercase Letters',
        passed: hasUppercase,
        detail: hasUppercase ? 'Present' : 'Missing',
      });

      const hasLowercase = /[a-z]/.test(password);
      checks.push({
        check: 'Lowercase Letters',
        passed: hasLowercase,
        detail: hasLowercase ? 'Present' : 'Missing',
      });

      const hasNumber = /[0-9]/.test(password);
      checks.push({
        check: 'Numbers',
        passed: hasNumber,
        detail: hasNumber ? 'Present' : 'Missing',
      });

      const hasSpecial = /[!@#$%^&*()_+\-=[\]{};':"\\|,.<>/?]/.test(password);
      checks.push({
        check: 'Special Characters',
        passed: hasSpecial,
        detail: hasSpecial ? 'Present' : 'Missing',
      });

      const commonPasswords = ['password', '123456', 'qwerty', 'admin', 'letmein', 'welcome'];
      const isCommon = commonPasswords.some((p) => password.toLowerCase().includes(p));
      checks.push({
        check: 'Common Password',
        passed: !isCommon,
        detail: isCommon ? 'WEAK: Contains common pattern' : 'No common patterns',
      });

      const hasSequential = /(?:abc|bcd|cde|123|234|345|456|567|678|789)/i.test(password);
      checks.push({
        check: 'Sequential Characters',
        passed: !hasSequential,
        detail: hasSequential ? 'WEAK: Contains sequences' : 'No sequences',
      });

      const hasRepeated = /(.)\1{2,}/.test(password);
      checks.push({
        check: 'Repeated Characters',
        passed: !hasRepeated,
        detail: hasRepeated ? 'WEAK: Contains repetitions' : 'No repetitions',
      });

      const entropy = calculateEntropy(password);
      checks.push({
        check: 'Entropy',
        passed: entropy > 50,
        detail: `${entropy.toFixed(2)} bits (>50 recommended)`,
      });

      const crackTime = estimateCrackTime(password);
      checks.push({
        check: 'Estimated Crack Time',
        passed: true,
        detail: crackTime,
      });

      setResults(checks);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Password Policy Checker',
        timestamp: Date.now(),
        input: { password: '*'.repeat(password.length) },
        output: checks,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Password check failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  const calculateEntropy = (str: string): number => {
    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    for (const count of Object.values(freq)) {
      const p = count / str.length;
      entropy -= p * Math.log2(p);
    }
    return entropy * str.length;
  };

  const estimateCrackTime = (pwd: string): string => {
    let charset = 0;
    if (/[a-z]/.test(pwd)) charset += 26;
    if (/[A-Z]/.test(pwd)) charset += 26;
    if (/[0-9]/.test(pwd)) charset += 10;
    if (/[^a-zA-Z0-9]/.test(pwd)) charset += 32;

    const combinations = Math.pow(charset, pwd.length);
    const guessesPerSecond = 1000000000;
    const seconds = combinations / guessesPerSecond;

    if (seconds < 1) return 'Instant';
    if (seconds < 60) return `${seconds.toFixed(0)} seconds`;
    if (seconds < 3600) return `${(seconds / 60).toFixed(0)} minutes`;
    if (seconds < 86400) return `${(seconds / 3600).toFixed(0)} hours`;
    if (seconds < 31536000) return `${(seconds / 86400).toFixed(0)} days`;
    return `${(seconds / 31536000).toFixed(0)} years`;
  };

  return (
    <ToolWrapper
      title="Password Policy Checker"
      icon={<LockIcon />}
      description="Analyze password strength and security policies"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Password to Analyze</label>
          <input
            type="text"
            className={styles.input}
            placeholder="Enter password to check"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={checkPassword} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Checking...
              </>
            ) : (
              'Check Password'
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className={styles.errorBox}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <span className={styles.resultTitle}>Password Strength Analysis</span>
          {results.map((result, idx) => (
            <div
              key={idx}
              className={styles.resultItem}
              style={{ flexDirection: 'column', alignItems: 'flex-start' }}
            >
              <div>
                <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                  {result.check}
                </span>
                <span style={{ color: result.passed ? '#00ff00' : '#ff4444', marginLeft: '10px' }}>
                  {result.passed ? '✓' : '✗'}
                </span>
              </div>
              <span
                style={{ color: '#666', fontSize: '11px', marginLeft: '10px', marginTop: '2px' }}
              >
                {result.detail}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default PasswordPolicyChecker;
