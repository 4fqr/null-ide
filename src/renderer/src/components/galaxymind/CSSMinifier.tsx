import { useState } from 'react';
import { CompressIcon, SparklesIcon, CopyIcon } from '../common/Icons';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';

export default function CSSMinifier() {
  const [input, setInput] = useState('');
  const [output, setOutput] = useState('');
  const [stats, setStats] = useState({ original: 0, minified: 0, saved: 0 });

  const minifyCSS = () => {
    let css = input;

    css = css.replace(/\/\*[\s\S]*?\*\
    css = css.replace(/\s*([{}:;,>+~])\s*/g, '$1');
    css = css.replace(/;}/g, '}');
    css = css.replace(/\s+/g, ' ');
    css = css.replace(/\s*\(\s*/g, '(');
    css = css.replace(/\s*\)\s*/g, ')');
    css = css.replace(/url\((['"]?)([^'"]+)\1\)/g, 'url($2)');
    css = css.replace(/#([0-9a-f])\1([0-9a-f])\2([0-9a-f])\3/gi, '#$1$2$3');
    css = css.replace(/(:|\s)0+\.(\d+)/g, '$1.$2');
    css = css.replace(/(:|\s)\.0([^\d]|$)/g, '$10$2');
    css = css.trim();

    setOutput(css);

    const originalSize = new Blob([input]).size;
    const minifiedSize = new Blob([css]).size;
    const savedSize = originalSize - minifiedSize;
    const savedPercent = originalSize > 0 ? ((savedSize / originalSize) * 100).toFixed(1) : 0;

    setStats({
      original: originalSize,
      minified: minifiedSize,
      saved: Number(savedPercent),
    });
  };

  const beautifyCSS = () => {
    let css = input;

    css = css.replace(/}/g, '}\n');
    css = css.replace(/{/g, ' {\n  ');
    css = css.replace(/;/g, ';\n  ');
    css = css.replace(/\n\s+}/g, '\n}');
    css = css.replace(/\n\s*\n/g, '\n');
    css = css.replace(/:/g, ': ');
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
    <ToolWrapper
      title="CSS Minifier"
      icon={<CompressIcon />}
      description="Minify or beautify CSS code"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Input CSS</label>
          <textarea
            className={styles.textarea}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Paste your CSS code here..."
          />
        </div>

        <div className={styles.buttonGroup}>
          <button onClick={minifyCSS} disabled={!input} className={styles.primaryBtn}>
            <CompressIcon /> Minify
          </button>
          <button onClick={beautifyCSS} disabled={!input} className={styles.secondaryBtn}>
            <SparklesIcon /> Beautify
          </button>
        </div>
      </div>

      {output && (
        <div className={styles.resultBox}>
          {stats.original > 0 && (
            <div className={styles.grid3} style={{ marginBottom: '16px' }}>
              <div className={styles.statCard}>
                <div className={styles.statLabel}>Original</div>
                <div className={styles.statValue}>{formatBytes(stats.original)}</div>
              </div>
              <div className={styles.statCard}>
                <div className={styles.statLabel}>Minified</div>
                <div className={styles.statValue}>{formatBytes(stats.minified)}</div>
              </div>
              <div className={styles.statCard}>
                <div className={styles.statLabel}>Saved</div>
                <div className={styles.statValueSuccess}>{stats.saved}%</div>
              </div>
            </div>
          )}

          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Output CSS</span>
            <button onClick={copyToClipboard} className={styles.copyBtn}>
              <CopyIcon /> Copy
            </button>
          </div>
          <textarea className={styles.textarea} value={output} readOnly />
        </div>
      )}
    </ToolWrapper>
  );
}
