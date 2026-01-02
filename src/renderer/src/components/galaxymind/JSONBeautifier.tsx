import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

const JSONBeautifier: React.FC = () => {
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [indentSize, setIndentSize] = useState(2);
  const [error, setError] = useState('');

  const beautify = () => {
    setError('');
    setOutput('');
    
    if (!input.trim()) {
      setError('Please enter JSON to beautify');
      return;
    }

    try {
      const parsed = JSON.parse(input);
      const beautified = JSON.stringify(parsed, null, indentSize);
      setOutput(beautified);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid JSON');
    }
  };

  const minify = () => {
    setError('');
    setOutput('');
    
    if (!input.trim()) {
      setError('Please enter JSON to minify');
      return;
    }

    try {
      const parsed = JSON.parse(input);
      const minified = JSON.stringify(parsed);
      setOutput(minified);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid JSON');
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(output);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>✨</span>
          JSON Beautifier
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Input JSON</label>
          <textarea
            className={styles.textarea}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder='{"name":"John","age":30,"city":"New York"}'
            rows={10}
          />
        </div>

        <div className={styles.controlsRow}>
          <div className={styles.inputGroup}>
            <label className={styles.label}>Indent Size</label>
            <input
              type="number"
              min="1"
              max="8"
              className={styles.input}
              value={indentSize}
              onChange={(e) => setIndentSize(Number(e.target.value))}
            />
          </div>

          <button onClick={beautify} className={styles.button}>
            ✨ Beautify
          </button>
          <button onClick={minify} className={styles.button}>
            🗜️ Minify
          </button>
        </div>

        {error && (
          <div className={styles.error}>{error}</div>
        )}

        {output && (
          <div className={styles.resultSection}>
            <div className={styles.resultHeader}>
              <label className={styles.label}>Output</label>
              <button onClick={copyToClipboard} className={styles.copyButton}>
                📋 Copy
              </button>
            </div>
            <textarea
              className={styles.textarea}
              value={output}
              readOnly
              rows={15}
            />
          </div>
        )}
      </div>
    </div>
  );
};

export default JSONBeautifier;
