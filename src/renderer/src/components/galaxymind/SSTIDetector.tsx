import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { MaskIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function SSTIDetector() {
  const [template, setTemplate] = useState('');
  const [engine, setEngine] = useState('auto');
  const [results, setResults] = useState<{ pattern: string; risk: string }[]>([]);
  const [error, setError] = useState('');

  const payloads: Record<string, string[]> = {
    jinja2: ['{{7*7}}', '{{config.items()}}', "{{''.__class__.__mro__}}"],
    erb: ['<%= 7*7 %>', '<%= `whoami` %>'],
    freemarker: ['${7*7}', '${"freemarker"}'],
    velocity: ['#set($x=7*7)$x'],
  };

  const detect = () => {
    setError('');
    setResults([]);

    if (!template.trim()) {
      setError('Please enter template content');
      return;
    }

    const patterns: { pattern: string; risk: string }[] = [];
    const t = template;

    if (t.includes('{{') || t.includes('}}')) {
      patterns.push({ pattern: 'Jinja2/Twig braces {{ }}', risk: 'High' });
    }
    if (t.includes('${') || t.includes('}')) {
      patterns.push({ pattern: 'FreeMarker/Velocity ${ }', risk: 'High' });
    }
    if (t.includes('<%') || t.includes('%>')) {
      patterns.push({ pattern: 'ERB/JSP tags <% %>', risk: 'High' });
    }
    if (t.includes('__class__') || t.includes('__mro__')) {
      patterns.push({ pattern: 'Python introspection', risk: 'Critical' });
    }
    if (t.includes('#set')) {
      patterns.push({ pattern: 'Velocity directive', risk: 'High' });
    }

    setResults(patterns);
  };

  return (
    <ToolWrapper
      title="SSTI Detector"
      icon={<MaskIcon />}
      description="Detect Server-Side Template Injection"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Template Engine</label>
          <select
            className={styles.select}
            value={engine}
            onChange={(e) => setEngine(e.target.value)}
          >
            <option value="auto">Auto-detect</option>
            <option value="jinja2">Jinja2 (Python)</option>
            <option value="erb">ERB (Ruby)</option>
            <option value="freemarker">FreeMarker (Java)</option>
            <option value="velocity">Velocity (Java)</option>
          </select>
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Template Input</label>
          <textarea
            className={styles.textarea}
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
            placeholder="Enter template to test..."
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={detect}>
            Detect SSTI
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setTemplate('');
              setResults([]);
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Detected Patterns</span>
          </div>
          {results.map((r, i) => (
            <div key={i} className={styles.resultItem}>
              <span
                className={r.risk === 'Critical' ? styles.badgeError : styles.badgeWarning}
                style={{ marginRight: '8px' }}
              >
                {r.risk}
              </span>
              {r.pattern}
            </div>
          ))}
        </div>
      )}

      <div className={styles.resultBox}>
        <div className={styles.resultHeader}>
          <span className={styles.resultTitle}>Test Payloads</span>
        </div>
        {Object.entries(payloads).map(([eng, plds]) => (
          <div key={eng} style={{ marginBottom: '12px' }}>
            <strong style={{ textTransform: 'capitalize', color: 'var(--color-accent)' }}>
              {eng}
            </strong>
            {plds.map((p, i) => (
              <div key={i} className={styles.code} style={{ marginTop: '4px' }}>
                {p}
              </div>
            ))}
          </div>
        ))}
      </div>

      <div className={styles.warningBox}>
        SSTI can lead to RCE. Only test on authorized systems.
      </div>
    </ToolWrapper>
  );
}
