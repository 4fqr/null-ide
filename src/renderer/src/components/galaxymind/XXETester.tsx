import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { DocumentIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function XXETester() {
  const [xmlInput, setXmlInput] = useState('');
  const [results, setResults] = useState<{ type: string; severity: string; description: string }[]>(
    []
  );
  const [error, setError] = useState('');

  const payloads = [
    {
      name: 'Basic XXE',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root><data>&xxe;</data></root>`,
    },
    {
      name: 'PHP Wrapper',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]>
<root><data>&xxe;</data></root>`,
    },
    {
      name: 'Billion Laughs',
      payload: `<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>
<root>&lol2;</root>`,
    },
  ];

  const analyze = () => {
    setError('');
    setResults([]);

    if (!xmlInput.trim()) {
      setError('Please enter XML content');
      return;
    }

    const vulnerabilities: { type: string; severity: string; description: string }[] = [];
    const xmlLower = xmlInput.toLowerCase();

    if (xmlLower.includes('<!doctype')) {
      vulnerabilities.push({
        type: 'DOCTYPE Declaration',
        severity: 'High',
        description: 'DOCTYPE may allow XXE attacks',
      });
    }

    if (xmlLower.includes('<!entity')) {
      vulnerabilities.push({
        type: 'Entity Declaration',
        severity: 'Critical',
        description: 'Entity declarations detected',
      });
    }

    if (
      xmlLower.includes('system') &&
      (xmlLower.includes('file://') || xmlLower.includes('http://'))
    ) {
      vulnerabilities.push({
        type: 'External Entity',
        severity: 'Critical',
        description: 'External entity reference detected',
      });
    }

    if (xmlLower.includes('php://')) {
      vulnerabilities.push({
        type: 'PHP Wrapper',
        severity: 'Critical',
        description: 'PHP wrapper detected',
      });
    }

    setResults(vulnerabilities);
  };

  const loadPayload = (payload: string) => setXmlInput(payload);

  return (
    <ToolWrapper
      title="XXE Tester"
      icon={<DocumentIcon />}
      description="Detect XML External Entity vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>XML Input</label>
          <textarea
            className={styles.textarea}
            value={xmlInput}
            onChange={(e) => setXmlInput(e.target.value)}
            placeholder="Paste XML here..."
            style={{ minHeight: '150px' }}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={analyze}>
            Analyze XML
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setXmlInput('');
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
            <span className={styles.resultTitle}>Vulnerabilities ({results.length})</span>
          </div>
          {results.map((r, i) => (
            <div key={i} className={styles.resultItem}>
              <div className={styles.flexRow} style={{ justifyContent: 'space-between' }}>
                <strong>{r.type}</strong>
                <span
                  className={r.severity === 'Critical' ? styles.badgeError : styles.badgeWarning}
                >
                  {r.severity}
                </span>
              </div>
              <span style={{ color: 'var(--color-text-tertiary)', fontSize: '13px' }}>
                {r.description}
              </span>
            </div>
          ))}
        </div>
      )}

      <div className={styles.resultBox}>
        <div className={styles.resultHeader}>
          <span className={styles.resultTitle}>XXE Payloads</span>
        </div>
        {payloads.map((p, i) => (
          <div key={i} className={styles.resultItem}>
            <div
              className={styles.flexRow}
              style={{ justifyContent: 'space-between', alignItems: 'center' }}
            >
              <strong>{p.name}</strong>
              <button className={styles.smallBtn} onClick={() => loadPayload(p.payload)}>
                Load
              </button>
            </div>
          </div>
        ))}
      </div>

      <div className={styles.warningBox}>
        Only test on systems you own. XXE can read sensitive files and perform SSRF.
      </div>
    </ToolWrapper>
  );
}
