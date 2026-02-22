import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import { CertificateIcon } from '../common/Icons';
import styles from './SharedTool.module.css';

export default function CertificateAnalyzer() {
  const [certificate, setCertificate] = useState('');
  const [results, setResults] = useState<{ field: string; value: string }[]>([]);
  const [error, setError] = useState('');

  const analyze = () => {
    setError('');
    setResults([]);

    if (!certificate.trim()) {
      setError('Please enter a certificate');
      return;
    }

    try {
      let certData = certificate.trim();
      certData = certData
        .replace(/-----BEGIN CERTIFICATE-----/g, '')
        .replace(/-----END CERTIFICATE-----/g, '')
        .replace(/\s/g, '');

      const decoded = atob(certData);
      const bytes = new Uint8Array(decoded.length);
      for (let i = 0; i < decoded.length; i++) bytes[i] = decoded.charCodeAt(i);

      const hexPreview = Array.from(bytes.slice(0, 50))
        .map((b) => b.toString(16).padStart(2, '0'))
        .join(' ');

      setResults([
        { field: 'Size', value: `${bytes.length} bytes` },
        { field: 'Format', value: 'X.509 DER/PEM' },
        { field: 'First 50 bytes (hex)', value: hexPreview },
        { field: 'ASN.1 Tag', value: bytes[0] === 0x30 ? 'SEQUENCE (valid)' : 'Unknown' },
      ]);
    } catch {
      setError('Invalid certificate format. Ensure PEM format with Base64 content.');
    }
  };

  const loadSample = () => {
    setCertificate(`-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKzDMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwODIzMDQxMDQ3WhcNMTgwODIzMDQxMDQ3WjBF
-----END CERTIFICATE-----`);
  };

  return (
    <ToolWrapper
      title="Certificate Analyzer"
      icon={<CertificateIcon />}
      description="Analyze X.509 SSL/TLS certificates"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Certificate (PEM format)</label>
          <textarea
            className={styles.textarea}
            value={certificate}
            onChange={(e) => setCertificate(e.target.value)}
            placeholder="Paste certificate..."
            style={{ minHeight: '150px' }}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={analyze}>
            Analyze
          </button>
          <button className={styles.secondaryBtn} onClick={loadSample}>
            Load Sample
          </button>
          <button
            className={styles.secondaryBtn}
            onClick={() => {
              setCertificate('');
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
            <span className={styles.resultTitle}>Certificate Details</span>
          </div>
          <table className={styles.table}>
            <tbody>
              {results.map((r, i) => (
                <tr key={i}>
                  <td>
                    <strong>{r.field}</strong>
                  </td>
                  <td className={styles.code}>{r.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>OpenSSL Commands</h3>
        <pre className={styles.codeBlock}>{`openssl x509 -in cert.pem -text -noout
openssl x509 -in cert.pem -noout -dates
openssl s_client -connect example.com:443`}</pre>
      </div>
    </ToolWrapper>
  );
}
