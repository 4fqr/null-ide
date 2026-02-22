import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { RegexIcon } from '../common/Icons';

export default function RegexTester() {
  const [pattern, setPattern] = useState('');
  const [flags, setFlags] = useState('gi');
  const [testString, setTestString] = useState('');
  const [matches, setMatches] = useState<RegExpMatchArray[]>([]);
  const [error, setError] = useState('');

  const handleTest = () => {
    setError('');
    setMatches([]);

    if (!pattern.trim()) {
      setError('Please enter a regex pattern');
      return;
    }

    if (!testString.trim()) {
      setError('Please enter test string');
      return;
    }

    try {
      const regex = new RegExp(pattern, flags);
      const foundMatches = Array.from(testString.matchAll(regex));
      setMatches(foundMatches);
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Invalid regex pattern';
      setError(errorMessage);
    }
  };

  const handleClear = () => {
    setPattern('');
    setTestString('');
    setMatches([]);
    setError('');
  };

  return (
    <ToolWrapper
      title="Regex Tester"
      icon={<RegexIcon />}
      description="Test regular expressions against sample text"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Regular Expression</label>
          <input
            type="text"
            className={styles.input}
            value={pattern}
            onChange={(e) => setPattern(e.target.value)}
            placeholder="e.g., \d{3}-\d{3}-\d{4}"
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Flags</label>
          <div className={styles.flexRow}>
            {[
              { flag: 'g', label: 'Global' },
              { flag: 'i', label: 'Case Insensitive' },
              { flag: 'm', label: 'Multiline' },
              { flag: 's', label: 'Dotall' },
            ].map(({ flag, label }) => (
              <label key={flag} className={styles.checkboxGroup}>
                <input
                  type="checkbox"
                  className={styles.checkbox}
                  checked={flags.includes(flag)}
                  onChange={(e) => {
                    if (e.target.checked) {
                      setFlags(flags + flag);
                    } else {
                      setFlags(flags.replace(flag, ''));
                    }
                  }}
                />
                <span style={{ fontSize: '0.875rem' }}>
                  {label} ({flag})
                </span>
              </label>
            ))}
          </div>
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Test String</label>
          <textarea
            className={styles.textarea}
            value={testString}
            onChange={(e) => setTestString(e.target.value)}
            placeholder="Enter text to test against regex..."
            rows={6}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={handleTest}>
            Test Regex
          </button>
          <button className={styles.secondaryBtn} onClick={handleClear}>
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {!error && matches.length > 0 && (
        <div className={styles.successBox}>
          Found {matches.length} match{matches.length !== 1 ? 'es' : ''}
        </div>
      )}

      {!error && testString && matches.length === 0 && !error && pattern && (
        <div style={{ padding: '1rem', color: 'var(--color-text-secondary)' }}>
          No matches found
        </div>
      )}

      {matches.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultTitle}>Matches ({matches.length})</div>
          {matches.map((match, index) => (
            <div key={index} className={styles.resultItem}>
              <div style={{ marginBottom: '0.5rem' }}>
                <span style={{ fontWeight: 600, color: 'var(--color-text-primary)' }}>
                  Match {index + 1}:
                </span>
                <span
                  style={{
                    marginLeft: '0.5rem',
                    fontFamily: 'var(--font-mono)',
                    color: 'var(--color-accent)',
                  }}
                >
                  {match[0]}
                </span>
              </div>
              {match.length > 1 && (
                <div>
                  <div
                    style={{
                      fontSize: '0.75rem',
                      color: 'var(--color-text-secondary)',
                      marginBottom: '0.25rem',
                    }}
                  >
                    Captured Groups:
                  </div>
                  {match.slice(1).map((group, gIndex) => (
                    <div
                      key={gIndex}
                      style={{
                        fontSize: '0.875rem',
                        fontFamily: 'var(--font-mono)',
                        color: 'var(--color-text-secondary)',
                        marginLeft: '1rem',
                      }}
                    >
                      ${gIndex + 1}: {group}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
