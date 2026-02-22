import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { JsonIcon, CopyIcon } from '../common/Icons';

export default function JSONFormatter() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState<'format' | 'minify'>('format');
  const [error, setError] = useState('');
  const [stats, setStats] = useState<{ valid: boolean; size: number } | null>(null);

  const handleProcess = () => {
    setError('');
    setOutput('');
    setStats(null);

    if (!input.trim()) {
      setError('Please enter JSON to process');
      return;
    }

    try {
      const parsed = JSON.parse(input);
      const processed =
        mode === 'format' ? JSON.stringify(parsed, null, 2) : JSON.stringify(parsed);
      setOutput(processed);
      setStats({
        valid: true,
        size: new Blob([processed]).size,
      });
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Invalid JSON';
      setError(`JSON Parse Error: ${errorMessage}`);
    }
  };

  const handleCopy = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  const handleClear = () => {
    setInput('');
    setOutput('');
    setError('');
    setStats(null);
  };

  return (
    <ToolWrapper
      title="JSON Formatter"
      icon={<JsonIcon />}
      description="Format or minify JSON data with validation"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Mode</label>
          <div className={styles.flexRow}>
            <button
              className={mode === 'format' ? styles.primaryBtn : styles.secondaryBtn}
              onClick={() => setMode('format')}
              style={{ flex: 1 }}
            >
              Format (Pretty)
            </button>
            <button
              className={mode === 'minify' ? styles.primaryBtn : styles.secondaryBtn}
              onClick={() => setMode('minify')}
              style={{ flex: 1 }}
            >
              Minify
            </button>
          </div>
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Input JSON</label>
          <textarea
            className={styles.textarea}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder='{"name":"John","age":30,"city":"New York"}'
            rows={8}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={handleProcess}>
            {mode === 'format' ? 'Format' : 'Minify'}
          </button>
          <button className={styles.secondaryBtn} onClick={handleClear}>
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {output && stats && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <div>
              <span className={styles.resultTitle}>Output</span>
              <span
                style={{
                  fontSize: '0.75rem',
                  color: 'var(--color-text-secondary)',
                  marginLeft: '12px',
                }}
              >
                Size: {stats.size} bytes
              </span>
            </div>
            <button className={styles.copyBtn} onClick={handleCopy}>
              <CopyIcon /> Copy
            </button>
          </div>
          <pre
            className={styles.codeBlock}
            style={{ maxHeight: '500px', overflow: 'auto', whiteSpace: 'pre-wrap' }}
          >
            {output}
          </pre>
        </div>
      )}
    </ToolWrapper>
  );
}
