import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { SparklesIcon, CompressIcon, CopyIcon } from '../common/Icons';

const JSONBeautifier: React.FC = () => {
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
    <ToolWrapper
      title="JSON Beautifier"
      icon={<SparklesIcon />}
      description="Format and beautify JSON data with customizable indentation"
    >
      <div className={styles.section}>
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

        <div className={styles.flexRow}>
          <div className={styles.inputGroup} style={{ flex: 0, minWidth: '100px' }}>
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
        </div>

        <div className={styles.buttonGroup}>
          <button onClick={beautify} className={styles.primaryBtn}>
            <SparklesIcon /> Beautify
          </button>
          <button onClick={minify} className={styles.secondaryBtn}>
            <CompressIcon /> Minify
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {output && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Output</span>
            <button onClick={copyToClipboard} className={styles.copyBtn}>
              <CopyIcon /> Copy
            </button>
          </div>
          <textarea className={styles.textarea} value={output} readOnly rows={15} />
        </div>
      )}
    </ToolWrapper>
  );
};

export default JSONBeautifier;
