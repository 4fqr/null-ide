import { useState } from 'react';
import styles from './Tool.module.css';

export default function LFIScanner() {
  const [targetUrl, setTargetUrl] = useState('');
  const [parameter, setParameter] = useState('file');
  const [scanning, setScanning] = useState(false);
  const [results, setResults] = useState<Array<{ payload: string; status: string }>>([]);
  const [summary, setSummary] = useState('');

  const lfiPayloads = [
    // Basic traversal
    '../../../etc/passwd',
    '..\\..\\..\\windows\\win.ini',
    
    // URL encoded
    '..%2F..%2F..%2Fetc%2Fpasswd',
    '..%5c..%5c..%5cwindows%5cwin.ini',
    
    // Double encoding
    '..%252F..%252F..%252Fetc%252Fpasswd',
    
    // Null byte
    '../../../etc/passwd%00',
    '../../../etc/passwd%00.jpg',
    
    // Wrapper protocols (PHP)
    'php://filter/convert.base64-encode/resource=index.php',
    'php://filter/read=string.rot13/resource=index.php',
    'file:///etc/passwd',
    
    // Long traversal
    '../../../../../../../../../etc/passwd',
    '....//....//....//etc/passwd',
    
    // Windows
    'C:\\windows\\system32\\drivers\\etc\\hosts',
    'C:/windows/system32/drivers/etc/hosts',
    
    // /proc
    '/proc/self/environ',
    '/proc/self/cmdline',
    
    // Log files
    '/var/log/apache2/access.log',
    '/var/log/nginx/access.log',
    '../../../../../../../var/log/apache2/access.log'
  ];

  const scanForLFI = async () => {
    if (!targetUrl.trim() || !parameter.trim()) {
      alert('Please enter target URL and parameter name');
      return;
    }

    setScanning(true);
    setResults([]);
    setSummary('Starting LFI scan...');

    const testResults: Array<{ payload: string; status: string }> = [];
    let vulnerableCount = 0;

    for (let i = 0; i < lfiPayloads.length; i++) {
      const payload = lfiPayloads[i];
      const separator = targetUrl.includes('?') ? '&' : '?';
      const testUrl = `${targetUrl}${separator}${parameter}=${encodeURIComponent(payload)}`;

      try {
        // In a real scanner, you would make HTTP requests here
        // For demo purposes, we'll simulate the scan
        await new Promise(resolve => setTimeout(resolve, 100));

        // Simulate some vulnerabilities for demo
        const isVulnerable = Math.random() < 0.15; // 15% chance for demo
        const status = isVulnerable ? '⚠️ Potentially Vulnerable' : '✓ No indication';

        if (isVulnerable) vulnerableCount++;

        testResults.push({ payload, status });
        setResults([...testResults]);

        setSummary(`Scanned ${i + 1}/${lfiPayloads.length} payloads - ${vulnerableCount} potential issues found`);
      } catch (error) {
        testResults.push({ payload, status: '✗ Error' });
        setResults([...testResults]);
      }
    }

    setSummary(
      `Scan complete: ${lfiPayloads.length} payloads tested, ${vulnerableCount} potential vulnerabilities detected`
    );
    setScanning(false);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>📁</span>
          LFI/RFI Scanner
        </div>
        <div className={styles.toolSubtitle}>
          Detect Local/Remote File Inclusion vulnerabilities
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label>Target URL</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com/page.php"
            disabled={scanning}
          />
        </div>

        <div className={styles.inputGroup}>
          <label>Parameter Name</label>
          <input
            type="text"
            value={parameter}
            onChange={(e) => setParameter(e.target.value)}
            placeholder="file"
            disabled={scanning}
          />
        </div>

        <button
          className={styles.primaryBtn}
          onClick={scanForLFI}
          disabled={scanning}
        >
          {scanning ? 'Scanning...' : 'Start Scan'}
        </button>

        {summary && (
          <div className={styles.outputSection}>
            <label>Scan Progress</label>
            <div className={styles.output}>{summary}</div>
          </div>
        )}

        {results.length > 0 && (
          <div className={styles.outputSection}>
            <label>Results ({results.length} payloads tested)</label>
            <div className={styles.output}>
              {results.map((result, idx) => (
                <div key={idx} style={{ marginBottom: '8px' }}>
                  <strong>{result.status}</strong>
                  <br />
                  <span style={{ opacity: 0.7 }}>Payload: {result.payload}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div className={styles.infoBox}>
          <h3>LFI/RFI Detection</h3>
          <p>This scanner tests for file inclusion vulnerabilities by attempting to access:</p>
          <ul>
            <li>System files (/etc/passwd, win.ini)</li>
            <li>Path traversal sequences (../, ..\\)</li>
            <li>Encoded variants (%2F, %5C, double encoding)</li>
            <li>Null byte injection (%00)</li>
            <li>PHP wrappers (php://filter, file://)</li>
            <li>Log files and /proc entries</li>
          </ul>
          <p className={styles.warning}>
            ⚠️ This is a DEMO scanner. Real scanning requires actual HTTP requests and response analysis. Use proper tools like Burp Suite or OWASP ZAP for production testing.
          </p>
        </div>
      </div>
    </div>
  );
}
