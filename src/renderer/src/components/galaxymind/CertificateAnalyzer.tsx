import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './Tool.module.css';

export default function CertificateAnalyzer() {
  const [certificate, setCertificate] = useState('');
  const [result, setResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);

  const analyzeCertificate = () => {
    setLoading(true);
    setResult(null);

    try {
      // Remove headers if present
      let certData = certificate.trim();
      certData = certData.replace(/-----BEGIN CERTIFICATE-----/g, '');
      certData = certData.replace(/-----END CERTIFICATE-----/g, '');
      certData = certData.replace(/\s/g, '');

      if (!certData) {
        throw new Error('Please provide a certificate');
      }

      // Decode base64
      const decoded = atob(certData);
      const bytes = new Uint8Array(decoded.length);
      for (let i = 0; i < decoded.length; i++) {
        bytes[i] = decoded.charCodeAt(i);
      }

      // Parse basic certificate structure
      const analysis: any = {
        valid: true,
        size: bytes.length,
        format: 'X.509',
        encoding: 'DER',
        details: {},
      };

      // Extract basic information from ASN.1 structure
      // This is a simplified parser - real certificates need full ASN.1 parsing
      const hexDump = Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join(' ');

      analysis.details = {
        totalBytes: bytes.length,
        hexPreview: hexDump.substring(0, 200) + '...',
        structure: {
          type: 'SEQUENCE',
          version: 'v3 (likely)',
        },
        warnings: [],
      };

      // Check certificate version (byte 2 usually indicates version)
      if (bytes[0] === 0x30) {
        analysis.details.asn1Valid = true;
        analysis.details.structure.rootTag = 'SEQUENCE (0x30)';
      }

      // Check for common patterns
      if (hexDump.includes('06 03 55 04')) {
        analysis.details.containsOID = true;
        analysis.details.warnings.push('Contains X.500 AttributeType OIDs');
      }

      // Size validation
      if (bytes.length < 100) {
        analysis.details.warnings.push('Certificate seems too small to be valid');
      } else if (bytes.length > 10000) {
        analysis.details.warnings.push('Unusually large certificate');
      }

      // Check for RSA signature (common pattern)
      if (hexDump.includes('06 09 2a 86 48 86 f7 0d 01 01')) {
        analysis.details.signatureAlgorithm = 'RSA (likely)';
      }

      // Security checks
      analysis.security = {
        encoding: 'PEM/DER',
        recommendations: [],
      };

      if (bytes.length < 512) {
        analysis.security.recommendations.push('⚠️ Very small certificate - may be invalid');
      }

      analysis.security.recommendations.push('✅ Successfully decoded from Base64');
      analysis.security.recommendations.push('ℹ️ Use OpenSSL for full certificate analysis');
      analysis.security.recommendations.push('ℹ️ Check expiry dates with: openssl x509 -text -noout');

      setResult(analysis);
    } catch (error: any) {
      setResult({
        valid: false,
        error: error.message,
        suggestions: [
          'Ensure certificate is in PEM format',
          'Certificate should be between BEGIN/END markers or pure base64',
          'Remove any extra whitespace or line breaks in base64',
        ],
      });
    } finally {
      setLoading(false);
    }
  };

  const loadSample = () => {
    // Sample self-signed certificate (shortened for demo)
    setCertificate(`-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+mRKzDMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwODIzMDQxMDQ3WhcNMTgwODIzMDQxMDQ3WjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA1234567890
-----END CERTIFICATE-----`);
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
          <h2 className={styles.title}>🔐 Certificate Analyzer</h2>
          <p className={styles.description}>Decode and analyze X.509 SSL/TLS certificates</p>
        </div>
      </div>

      <div className={styles.content}>
        <div className={styles.section}>
          <label className={styles.label}>Certificate (PEM format)</label>
          <textarea
            className={styles.textarea}
            value={certificate}
            onChange={(e) => setCertificate(e.target.value)}
            placeholder="Paste certificate here (with or without BEGIN/END markers)..."
            rows={12}
          />
          <div className={styles.buttonGroup}>
            <button className={styles.button} onClick={analyzeCertificate} disabled={loading}>
              {loading ? 'Analyzing...' : 'Analyze Certificate'}
            </button>
            <button className={styles.buttonSecondary} onClick={loadSample}>
              Load Sample
            </button>
            <button className={styles.buttonSecondary} onClick={() => setCertificate('')}>
              Clear
            </button>
          </div>
        </div>

        {result && (
          <div className={styles.section}>
            <h3 className={styles.subtitle}>Analysis Results</h3>
            <div className={styles.result}>
              {result.valid ? (
                <div className={styles.successResult}>
                  <h4>✅ Certificate Decoded Successfully</h4>
                  <div className={styles.info}>
                    <strong>Format:</strong> {result.format}
                  </div>
                  <div className={styles.info}>
                    <strong>Encoding:</strong> {result.encoding}
                  </div>
                  <div className={styles.info}>
                    <strong>Size:</strong> {result.size} bytes
                  </div>

                  {result.details && (
                    <>
                      <h4 style={{ marginTop: '1rem' }}>Certificate Details</h4>
                      <div className={styles.codeBlock}>
                        <pre>{JSON.stringify(result.details, null, 2)}</pre>
                      </div>
                    </>
                  )}

                  {result.security && (
                    <>
                      <h4 style={{ marginTop: '1rem' }}>Security Analysis</h4>
                      <div className={styles.recommendations}>
                        {result.security.recommendations.map((rec: string, idx: number) => (
                          <div key={idx} className={styles.recommendation}>
                            {rec}
                          </div>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              ) : (
                <div className={styles.errorResult}>
                  <h4>❌ Analysis Failed</h4>
                  <div className={styles.error}>{result.error}</div>
                  {result.suggestions && (
                    <>
                      <h4 style={{ marginTop: '1rem' }}>Suggestions:</h4>
                      <ul>
                        {result.suggestions.map((sug: string, idx: number) => (
                          <li key={idx}>{sug}</li>
                        ))}
                      </ul>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        <div className={styles.section}>
          <h3 className={styles.subtitle}>OpenSSL Commands</h3>
          <div className={styles.codeBlock}>
            <pre>{`# View certificate details
openssl x509 -in cert.pem -text -noout

# Check certificate expiry
openssl x509 -in cert.pem -noout -dates

# Verify certificate chain
openssl verify -CAfile ca.pem cert.pem

# Extract public key
openssl x509 -in cert.pem -pubkey -noout

# Check certificate's signature algorithm
openssl x509 -in cert.pem -noout -text | grep "Signature Algorithm"

# Test SSL/TLS connection
openssl s_client -connect example.com:443`}</pre>
          </div>
        </div>
      </div>
    </div>
  );
}
