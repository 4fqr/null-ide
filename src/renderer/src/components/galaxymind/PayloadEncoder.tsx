import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { EncodeIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

type EncodingType = 'base64' | 'url' | 'hex' | 'unicode' | 'double-url' | 'html-entities';

export default function PayloadEncoder() {
  const [payload, setPayload] = useState('');
  const [encodingType, setEncodingType] = useState<EncodingType>('base64');
  const [output, setOutput] = useState('');
  const [error, setError] = useState('');

  const encode = () => {
    setError('');
    if (!payload.trim()) {
      setError('Please enter a payload');
      return;
    }

    try {
      let result = '';
      switch (encodingType) {
        case 'base64':
          result = btoa(payload);
          break;
        case 'url':
          result = encodeURIComponent(payload);
          break;
        case 'hex':
          result = Array.from(payload)
            .map((c) => c.charCodeAt(0).toString(16).padStart(2, '0'))
            .join('');
          break;
        case 'unicode':
          result = Array.from(payload)
            .map((c) => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
            .join('');
          break;
        case 'double-url':
          result = encodeURIComponent(encodeURIComponent(payload));
          break;
        case 'html-entities':
          result = Array.from(payload)
            .map((c) => '&#' + c.charCodeAt(0) + ';')
            .join('');
          break;
      }
      setOutput(result);
    } catch {
      setError('Failed to encode payload');
    }
  };

  const decode = () => {
    setError('');
    if (!payload.trim()) {
      setError('Please enter an encoded payload');
      return;
    }

    try {
      let result = '';
      switch (encodingType) {
        case 'base64':
          result = atob(payload);
          break;
        case 'url':
          result = decodeURIComponent(payload);
          break;
        case 'hex':
          result =
            payload
              .match(/.{1,2}/g)
              ?.map((b) => String.fromCharCode(parseInt(b, 16)))
              .join('') || '';
          break;
        case 'unicode':
          result = payload.replace(/\\u[\dA-Fa-f]{4}/g, (m) =>
            String.fromCharCode(parseInt(m.replace('\\u', ''), 16))
          );
          break;
        case 'double-url':
          result = decodeURIComponent(decodeURIComponent(payload));
          break;
        case 'html-entities':
          result = payload.replace(/&#(\d+);/g, (_, dec) => String.fromCharCode(parseInt(dec)));
          break;
      }
      setOutput(result);
    } catch {
      setError('Failed to decode payload - invalid format');
    }
  };

  return (
    <ToolWrapper
      title="Payload Encoder"
      icon={<EncodeIcon />}
      description="Encode and decode payloads for bypass testing"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Encoding Type</label>
          <select
            className={styles.select}
            value={encodingType}
            onChange={(e) => setEncodingType(e.target.value as EncodingType)}
          >
            <option value="base64">Base64</option>
            <option value="url">URL Encoding</option>
            <option value="hex">Hexadecimal</option>
            <option value="unicode">Unicode Escape</option>
            <option value="double-url">Double URL Encoding</option>
            <option value="html-entities">HTML Entities</option>
          </select>
        </div>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Payload</label>
          <textarea
            className={styles.textarea}
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder="Enter payload to encode/decode..."
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={encode}>
            Encode
          </button>
          <button className={styles.secondaryBtn} onClick={decode}>
            Decode
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setPayload('');
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
            <span className={styles.resultTitle}>Output</span>
            <button
              className={styles.copyBtn}
              onClick={() => navigator.clipboard.writeText(output)}
            >
              Copy
            </button>
          </div>
          <div className={styles.resultContent}>{output}</div>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>Encoding Techniques</h3>
        <ul>
          <li>
            <strong>Base64:</strong> Standard encoding for binary data
          </li>
          <li>
            <strong>URL:</strong> Percent-encoding special characters
          </li>
          <li>
            <strong>Hex:</strong> Hexadecimal representation
          </li>
          <li>
            <strong>Unicode:</strong> JavaScript/Java unicode escape sequences
          </li>
          <li>
            <strong>Double URL:</strong> Encode twice to bypass decode-then-filter logic
          </li>
          <li>
            <strong>HTML Entities:</strong> Numeric character references
          </li>
        </ul>
      </div>
    </ToolWrapper>
  );
}
