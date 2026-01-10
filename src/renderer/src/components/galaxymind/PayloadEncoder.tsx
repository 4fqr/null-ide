import { useState } from 'react';
import styles from './Tool.module.css';

type EncodingType = 'base64' | 'url' | 'hex' | 'unicode' | 'double-url' | 'html-entities';

export default function PayloadEncoder() {
  const [payload, setPayload] = useState('');
  const [encodingType, setEncodingType] = useState<EncodingType>('base64');
  const [encoded, setEncoded] = useState('');

  const encodePayload = () => {
    if (!payload.trim()) return;

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
          .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
          .join('');
        break;
      case 'unicode':
        result = Array.from(payload)
          .map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0'))
          .join('');
        break;
      case 'double-url':
        result = encodeURIComponent(encodeURIComponent(payload));
        break;
      case 'html-entities':
        result = Array.from(payload)
          .map(c => '&#' + c.charCodeAt(0) + ';')
          .join('');
        break;
    }
    setEncoded(result);
  };

  const decodePayload = () => {
    if (!encoded.trim()) return;

    try {
      let result = '';
      switch (encodingType) {
        case 'base64':
          result = atob(encoded);
          break;
        case 'url':
          result = decodeURIComponent(encoded);
          break;
        case 'hex':
          result = encoded.match(/.{1,2}/g)
            ?.map(byte => String.fromCharCode(parseInt(byte, 16)))
            .join('') || '';
          break;
        case 'unicode':
          result = encoded.replace(/\\u[\dA-Fa-f]{4}/g, match =>
            String.fromCharCode(parseInt(match.replace('\\u', ''), 16))
          );
          break;
        case 'double-url':
          result = decodeURIComponent(decodeURIComponent(encoded));
          break;
        case 'html-entities':
          result = encoded.replace(/&#(\d+);/g, (match, dec) =>
            String.fromCharCode(parseInt(dec))
          );
          break;
      }
      setPayload(result);
    } catch (error) {
      alert('Failed to decode: Invalid format');
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(encoded);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔐</span>
          Payload Encoder
        </div>
        <div className={styles.toolSubtitle}>
          Encode/decode payloads to bypass WAF filters and input validation
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.inputGroup}>
          <label>Encoding Type</label>
          <select
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
          <label>Original Payload</label>
          <textarea
            value={payload}
            onChange={(e) => setPayload(e.target.value)}
            placeholder="Enter payload to encode..."
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={encodePayload}>
            Encode
          </button>
          <button className={styles.secondaryBtn} onClick={decodePayload}>
            Decode
          </button>
        </div>

        {encoded && (
          <div className={styles.outputSection}>
            <div className={styles.outputHeader}>
              <label>Encoded Payload</label>
              <button className={styles.copyBtn} onClick={copyToClipboard}>
                Copy
              </button>
            </div>
            <div className={styles.output}>{encoded}</div>
          </div>
        )}

        <div className={styles.infoBox}>
          <h3>Encoding Techniques</h3>
          <ul>
            <li><strong>Base64:</strong> Standard encoding for binary data, bypasses basic filters</li>
            <li><strong>URL:</strong> Percent-encoding special characters (%20, %3C, etc.)</li>
            <li><strong>Hex:</strong> Convert to hexadecimal representation</li>
            <li><strong>Unicode:</strong> JavaScript/Java unicode escape sequences (\u0041)</li>
            <li><strong>Double URL:</strong> Encode twice to bypass decode-then-filter logic</li>
            <li><strong>HTML Entities:</strong> Numeric character references (&#60;)</li>
          </ul>
          <p className={styles.warning}>
            ⚠️ Use responsibly. Encoding bypasses may violate security policies.
          </p>
        </div>
      </div>
    </div>
  );
}
