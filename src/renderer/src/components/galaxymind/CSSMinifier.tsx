import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

const CSSMinifier: React.FC = () => {
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [stats, setStats] = useState({ original: 0, minified: 0, saved: 0 });

  const minifyCSS = () => {
    let css = input;

    // Remove comments
    css = css.replace(/\/\*[\s\S]*?\*\//g, '');

    // Remove whitespace around special characters
    css = css.replace(/\s*([{}:;,>+~])\s*/g, '$1');

    // Remove trailing semicolons
    css = css.replace(/;}/g, '}');

    // Remove unnecessary spaces
    css = css.replace(/\s+/g, ' ');

    // Remove spaces around parentheses
    css = css.replace(/\s*\(\s*/g, '(');
    css = css.replace(/\s*\)\s*/g, ')');

    // Remove quotes from URLs when possible
    css = css.replace(/url\((['"]?)([^'"]+)\1\)/g, 'url($2)');

    // Convert HEX colors to shorthand
    css = css.replace(/#([0-9a-f])\1([0-9a-f])\2([0-9a-f])\3/gi, '#$1$2$3');

    // Remove leading zeros
    css = css.replace(/(:|\s)0+\.(\d+)/g, '$1.$2');

    // Remove unnecessary zeros
    css = css.replace(/(:|\s)\.0([^\d]|$)/g, '$10$2');

    // Trim
    css = css.trim();

    setOutput(css);

    const originalSize = new Blob([input]).size;
    const minifiedSize = new Blob([css]).size;
    const savedSize = originalSize - minifiedSize;
    const savedPercent = originalSize > 0 ? ((savedSize / originalSize) * 100).toFixed(1) : 0;

    setStats({
      original: originalSize,
      minified: minifiedSize,
      saved: Number(savedPercent)
    });
  };

  const beautifyCSS = () => {
    let css = input;

    // Add newlines after braces
    css = css.replace(/}/g, '}\n');
    css = css.replace(/{/g, ' {\n  ');

    // Add newlines after semicolons
    css = css.replace(/;/g, ';\n  ');

    // Fix indentation
    css = css.replace(/\n\s+}/g, '\n}');

    // Remove extra whitespace
    css = css.replace(/\n\s*\n/g, '\n');

    // Add space after colons
    css = css.replace(/:/g, ': ');

    // Trim
    css = css.trim();

    setOutput(css);
    setStats({ original: 0, minified: 0, saved: 0 });
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(output);
  };

  const formatBytes = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🗜️</span>
          CSS Minifier
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Input CSS</label>
          <textarea
            className={styles.textarea}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Paste your CSS code here...&#10;&#10;.example {&#10;  color: #ffffff;&#10;  margin: 0px;&#10;  padding: 10px;&#10;}"
            rows={12}
          />
        </div>

        <div className={styles.actions}>
          <button onClick={minifyCSS} disabled={!input} className={styles.button}>
            🗜️ Minify
          </button>
          <button onClick={beautifyCSS} disabled={!input} className={styles.button}>
            ✨ Beautify
          </button>
        </div>

        {output && (
          <>
            {stats.original > 0 && (
              <div className={styles.statsContainer}>
                <div className={styles.stat}>
                  <span className={styles.statLabel}>Original:</span>
                  <span className={styles.statValue}>{formatBytes(stats.original)}</span>
                </div>
                <div className={styles.stat}>
                  <span className={styles.statLabel}>Minified:</span>
                  <span className={styles.statValue}>{formatBytes(stats.minified)}</span>
                </div>
                <div className={styles.stat}>
                  <span className={styles.statLabel}>Saved:</span>
                  <span className={styles.statValue}>{stats.saved}%</span>
                </div>
              </div>
            )}

            <div className={styles.resultSection}>
              <div className={styles.resultHeader}>
                <label className={styles.label}>Output CSS</label>
                <button onClick={copyToClipboard} className={styles.copyButton}>
                  📋 Copy
                </button>
              </div>
              <textarea
                className={styles.textarea}
                value={output}
                readOnly
                rows={12}
              />
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default CSSMinifier;
