import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { EntityIcon, CopyIcon } from '../common/Icons';

export default function HTMLEntityEncoder() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState<'encode' | 'decode'>('encode');

  const entities: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&apos;',
    '©': '&copy;',
    '®': '&reg;',
    '™': '&trade;',
    '€': '&euro;',
    '£': '&pound;',
    '¥': '&yen;',
  };

  const handleProcess = () => {
    if (!input.trim()) {
      setOutput('Please enter text');
      return;
    }

    if (mode === 'encode') {
      let encoded = input;
      for (const [char, entity] of Object.entries(entities)) {
        encoded = encoded.split(char).join(entity);
      }
      setOutput(encoded);
    } else {
      const div = document.createElement('div');
      div.innerHTML = input;
      setOutput(div.textContent || div.innerText || '');
    }
  };

  const handleCopy = () => {
    if (output) {
      navigator.clipboard.writeText(output);
    }
  };

  return (
    <ToolWrapper
      title="HTML Entity Encoder"
      icon={<EntityIcon />}
      description="Encode or decode HTML entities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Mode</label>
          <div className={styles.flexRow}>
            <button
              className={`${styles.primaryBtn} ${mode === 'decode' ? styles.secondaryBtn : ''}`}
              onClick={() => setMode('encode')}
              style={{ flex: 1 }}
            >
              Encode
            </button>
            <button
              className={`${styles.primaryBtn} ${mode === 'encode' ? styles.secondaryBtn : ''}`}
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
                ? 'Enter text with special characters: <, >, &, ", etc.'
                : 'Enter HTML entities: &lt;, &gt;, &amp;, etc.'
            }
            rows={6}
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
            }}
          >
            Clear
          </button>
        </div>
      </div>

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
