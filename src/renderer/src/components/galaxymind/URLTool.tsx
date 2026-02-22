import { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { LinkIcon, CopyIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

export default function URLTool() {
  const addToolResult = useStore((state) => state.addToolResult);
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
        const encoded = encodeURIComponent(input);
        setOutput(encoded);
        addToolResult({
          id: Date.now().toString(),
          toolName: 'URL Encoder/Decoder',
          timestamp: Date.now(),
          input: { input, mode },
          output: encoded,
          success: true,
        });
      } else {
        const decoded = decodeURIComponent(input);
        setOutput(decoded);
        addToolResult({
          id: Date.now().toString(),
          toolName: 'URL Encoder/Decoder',
          timestamp: Date.now(),
          input: { input, mode },
          output: decoded,
          success: true,
        });
      }
    } catch (err) {
      setError('Invalid input. Please check your text.');
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
  };

  return (
    <ToolWrapper
      title="URL Encoder/Decoder"
      icon={<LinkIcon />}
      description="Encode or decode URL strings"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Mode</label>
          <div className={styles.flexRow}>
            <button
              className={mode === 'encode' ? styles.primaryBtn : styles.secondaryBtn}
              onClick={() => setMode('encode')}
              style={{ flex: 1 }}
            >
              Encode
            </button>
            <button
              className={mode === 'decode' ? styles.primaryBtn : styles.secondaryBtn}
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
              mode === 'encode'
                ? 'Enter text to URL encode...'
                : 'Enter URL encoded text to decode...'
            }
            rows={6}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={handleProcess}>
            {mode === 'encode' ? 'Encode' : 'Decode'}
          </button>
          <button className={styles.secondaryBtn} onClick={handleClear}>
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {output && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <div className={styles.resultTitle}>Output</div>
            <button className={styles.copyBtn} onClick={handleCopy}>
              <CopyIcon /> Copy
            </button>
          </div>
          <div className={styles.resultContent}>{output}</div>
        </div>
      )}
    </ToolWrapper>
  );
}
