import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

const SlugGenerator: React.FC = () => {
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);
  const [input, setInput] = useState('');
  const [separator, setSeparator] = useState('-');
  const [lowercase, setLowercase] = useState(true);
  const [removeSpecial, setRemoveSpecial] = useState(true);

  const generateSlug = (text: string): string => {
    let slug = text;

    // Convert to lowercase
    if (lowercase) {
      slug = slug.toLowerCase();
    }

    // Replace spaces with separator
    slug = slug.replace(/\s+/g, separator);

    // Remove special characters
    if (removeSpecial) {
      slug = slug.replace(/[^a-zA-Z0-9-_]/g, '');
    }

    // Remove multiple consecutive separators
    const escapedSep = separator.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    slug = slug.replace(new RegExp(`${escapedSep}+`, 'g'), separator);

    // Trim separators from start and end
    slug = slug.replace(new RegExp(`^${escapedSep}+|${escapedSep}+$`, 'g'), '');

    return slug;
  };

  const slug = input ? generateSlug(input) : '';

  const copyToClipboard = () => {
    navigator.clipboard.writeText(slug);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔗</span>
          Slug Generator
        </div>
      </div>

      <div className={styles.toolContent}>
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

        <div className={styles.optionsGrid}>
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

          <div className={styles.checkboxGroup}>
            <label className={styles.checkboxLabel}>
              <input
                type="checkbox"
                checked={lowercase}
                onChange={(e) => setLowercase(e.target.checked)}
              />
              Convert to lowercase
            </label>
          </div>

          <div className={styles.checkboxGroup}>
            <label className={styles.checkboxLabel}>
              <input
                type="checkbox"
                checked={removeSpecial}
                onChange={(e) => setRemoveSpecial(e.target.checked)}
              />
              Remove special characters
            </label>
          </div>
        </div>

        {slug && (
          <div className={styles.resultSection}>
            <div className={styles.resultHeader}>
              <label className={styles.label}>Generated Slug</label>
              <button onClick={copyToClipboard} className={styles.copyButton}>
                📋 Copy
              </button>
            </div>
            <div className={styles.resultBox}>
              <code>{slug}</code>
            </div>

            <div className={styles.exampleUsage}>
              <h4>Example Usage:</h4>
              <code>https://example.com/blog/{slug}</code>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SlugGenerator;
