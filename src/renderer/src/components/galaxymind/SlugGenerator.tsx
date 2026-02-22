import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { SlugIcon, CopyIcon } from '../common/Icons';

const SlugGenerator: React.FC = () => {
  const [input, setInput] = useState('');
  const [separator, setSeparator] = useState('-');
  const [lowercase, setLowercase] = useState(true);
  const [removeSpecial, setRemoveSpecial] = useState(true);

  const generateSlug = (text: string): string => {
    let slug = text;

    if (lowercase) {
      slug = slug.toLowerCase();
    }

    slug = slug.replace(/\s+/g, separator);

    if (removeSpecial) {
      slug = slug.replace(/[^a-zA-Z0-9-_]/g, '');
    }

    const escapedSep = separator.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    slug = slug.replace(new RegExp(`${escapedSep}+`, 'g'), separator);

    slug = slug.replace(new RegExp(`^${escapedSep}+|${escapedSep}+$`, 'g'), '');

    return slug;
  };

  const slug = input ? generateSlug(input) : '';

  const copyToClipboard = () => {
    navigator.clipboard.writeText(slug);
  };

  return (
    <ToolWrapper
      title="Slug Generator"
      icon={<SlugIcon />}
      description="Convert text to URL-friendly slugs"
    >
      <div className={styles.inputGroup}>
        <label className={styles.label}>Input Text</label>
        <input
          type="text"
          className={styles.input}
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Enter text to convert to slug..."
        />
      </div>

      <div className={styles.grid2}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Separator</label>
          <select
            className={styles.select}
            value={separator}
            onChange={(e) => setSeparator(e.target.value)}
          >
            <option value="-">Hyphen (-)</option>
            <option value="_">Underscore (_)</option>
            <option value=".">Dot (.)</option>
          </select>
        </div>
      </div>

      <div className={styles.checkboxGroup}>
        <label className={styles.checkbox}>
          <input
            type="checkbox"
            checked={lowercase}
            onChange={(e) => setLowercase(e.target.checked)}
          />
        </label>
        <span>Convert to lowercase</span>
      </div>

      <div className={styles.checkboxGroup}>
        <label className={styles.checkbox}>
          <input
            type="checkbox"
            checked={removeSpecial}
            onChange={(e) => setRemoveSpecial(e.target.checked)}
          />
        </label>
        <span>Remove special characters</span>
      </div>

      {slug && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Generated Slug</span>
            <button onClick={copyToClipboard} className={styles.copyBtn}>
              <CopyIcon /> Copy
            </button>
          </div>
          <div className={styles.codeBlock}>{slug}</div>

          <div className={styles.infoBox}>
            <h4>Example Usage:</h4>
            <p>
              <code>https://example.com/blog/{slug}</code>
            </p>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default SlugGenerator;
