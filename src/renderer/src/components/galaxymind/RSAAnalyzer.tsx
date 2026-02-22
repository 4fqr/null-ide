import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { LockIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

interface RSAAnalysis {
  keySize: number;
  strength: string;
  exponent: string;
  vulnerabilities: string[];
  recommendations: string[];
}

export const RSAAnalyzer: React.FC = () => {
  const { addToolResult } = useStore();
  const [publicKey, setPublicKey] = useState('');
  const [modulus, setModulus] = useState('');
  const [exponent, setExponent] = useState('65537');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<RSAAnalysis | null>(null);

  const analyzeRSA = async () => {
    if (!modulus) return;

    setLoading(true);
    setResult(null);

    try {
      const vulnerabilities: string[] = [];
      const recommendations: string[] = [];

      const cleanModulus = modulus.replace(/\s+/g, '');
      const keySize = cleanModulus.length * 4;

      let strength = 'Unknown';

      if (keySize < 1024) {
        strength = 'CRITICALLY WEAK';
        vulnerabilities.push('Key size < 1024 bits - easily factored');
        recommendations.push('Use minimum 2048-bit keys');
      } else if (keySize < 2048) {
        strength = 'WEAK';
        vulnerabilities.push('Key size < 2048 bits - deprecated by NIST');
        recommendations.push('Upgrade to 2048-bit or 4096-bit keys');
      } else if (keySize >= 2048 && keySize < 4096) {
        strength = 'ADEQUATE';
        recommendations.push('Consider 4096-bit keys for long-term security');
      } else {
        strength = 'STRONG';
      }

      const e = parseInt(exponent);
      if (e === 3) {
        vulnerabilities.push('Small exponent (e=3) vulnerable to cube root attack');
        recommendations.push('Use e=65537 (F4) instead');
      } else if (e < 65537 && e !== 3) {
        vulnerabilities.push(`Unusual exponent (e=${e}) may indicate weak implementation`);
      }

      if (cleanModulus.match(/^(00)+/)) {
        vulnerabilities.push('Leading zeros detected - possible padding issue');
      }

      const uniqueChars = new Set(cleanModulus.toLowerCase().split('')).size;
      if (uniqueChars < 10) {
        vulnerabilities.push('Low entropy in modulus - may not be truly random');
        recommendations.push('Ensure proper random number generation');
      }

      const modulusNum = BigInt('0x' + cleanModulus.substring(0, 32));
      const sqrtApprox = Math.floor(Math.sqrt(Number(modulusNum & BigInt(0xffffffff))));
      if (sqrtApprox > 0) {
        const diff = Math.abs(sqrtApprox * sqrtApprox - Number(modulusNum & BigInt(0xffffffff)));
        if (diff < 1000) {
          vulnerabilities.push('Factors may be close together - Fermat attack possible');
          recommendations.push('Ensure p and q are sufficiently different');
        }
      }

      if (recommendations.length === 0) {
        recommendations.push('Key appears reasonably secure');
        recommendations.push('Continue following RSA best practices');
        recommendations.push('Consider transitioning to elliptic curve cryptography');
      }

      const analysis: RSAAnalysis = {
        keySize,
        strength,
        exponent,
        vulnerabilities,
        recommendations,
      };

      setResult(analysis);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'RSA Analyzer',
        input: { modulus, exponent, publicKey },
        output: analysis,
        success: true,
        timestamp: Date.now(),
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setResult({
        keySize: 0,
        strength: 'Error',
        exponent: '',
        vulnerabilities: [`Error: ${errorMsg}`],
        recommendations: [],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="RSA Key Strength Analyzer"
      icon={<LockIcon />}
      description="Analyze RSA public keys for cryptographic weaknesses"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>RSA Modulus (n) - Hex:</label>
          <textarea
            value={modulus}
            onChange={(e) => setModulus(e.target.value)}
            placeholder="Enter RSA modulus in hexadecimal..."
            className={styles.textarea}
            rows={6}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Public Exponent (e):</label>
          <input
            type="text"
            value={exponent}
            onChange={(e) => setExponent(e.target.value)}
            placeholder="65537"
            className={styles.input}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Or paste full public key (PEM):</label>
          <textarea
            value={publicKey}
            onChange={(e) => setPublicKey(e.target.value)}
            placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"
            className={styles.textarea}
            rows={4}
          />
        </div>

        <button onClick={analyzeRSA} disabled={loading || !modulus} className={styles.primaryBtn}>
          {loading ? (
            <>
              <LoadingIcon /> Analyzing...
            </>
          ) : (
            'Analyze RSA Key'
          )}
        </button>
      </div>

      {result && (
        <div className={styles.resultBox}>
          <div className={styles.resultTitle}>RSA Analysis Results</div>
          <div className={styles.resultItem}>
            <strong>Key Size:</strong> {result.keySize} bits
          </div>
          <div className={styles.resultItem}>
            <strong>Strength:</strong>{' '}
            <span
              style={{
                color: result.strength.includes('WEAK')
                  ? '#ff4444'
                  : result.strength === 'ADEQUATE'
                    ? '#ffaa00'
                    : '#44ff44',
              }}
            >
              {result.strength}
            </span>
          </div>
          <div className={styles.resultItem}>
            <strong>Public Exponent:</strong> {result.exponent}
          </div>
          {result.vulnerabilities.length > 0 && (
            <div className={styles.resultItem}>
              <strong>Vulnerabilities:</strong>
              <ul>
                {result.vulnerabilities.map((vuln, idx) => (
                  <li key={idx} style={{ color: '#ff4444' }}>
                    {vuln}
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className={styles.resultItem}>
            <strong>Recommendations:</strong>
            <ul>
              {result.recommendations.map((rec, idx) => (
                <li key={idx}>{rec}</li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default RSAAnalyzer;
