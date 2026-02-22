import { useState } from 'react';
import { EncryptIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

export default function Base64Tool() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState<'encode' | 'decode'>('encode');
  const [error, setError] = useState('');

  const handleProcess = () => {
    setError('');
    setOutput('');

    if (!input.trim()) {
      setError('Please enter text to process');
      return;
    }

    try {
      if (mode === 'encode') {
        setOutput(btoa(input));
      } else {
        setOutput(atob(input));
      }
    } catch {
      setError(mode === 'decode' ? 'Invalid Base64 input' : 'Failed to encode');
    }
  };

  const copyToClipboard = () => {
    if (output) navigator.clipboard.writeText(output);
  };

  return (
    <ToolWrapper
      title="Base64 Encoder/Decoder"
      icon={<EncryptIcon />}
      description="Encode and decode Base64 strings"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Mode</label>
          <div className={styles.flexRow}>
            <button
              className={`${styles.primaryBtn} ${mode !== 'encode' ? styles.secondaryBtn : ''}`}
              onClick={() => setMode('encode')}
              style={{ flex: 1 }}
            >
              Encode
            </button>
            <button
              className={`${styles.primaryBtn} ${mode !== 'decode' ? styles.secondaryBtn : ''}`}
              onClick={() => setMode('decode')}
              style={{ flex: 1 }}
            >
              Decode
            </button>
          </div>
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Input</label>
          <textarea
            className={styles.textarea}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder={
              mode === 'encode' ? 'Enter text to encode...' : 'Enter Base64 to decode...'
            }
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={handleProcess}>
            {mode === 'encode' ? 'Encode' : 'Decode'}
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setInput('');
              setOutput('');
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
            <span className={styles.resultTitle}>Output</span>
            <button className={styles.copyBtn} onClick={copyToClipboard}>
              Copy
            </button>
          </div>
          <div className={styles.resultContent}>{output}</div>
        </div>
      )}
    </ToolWrapper>
  );
}
