import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { LockIcon, LoadingIcon } from '../common/Icons';

interface TestResult {
  blockSize: number;
  hasPaddingOracle: boolean;
  decryptedData?: string;
  details: string[];
}

export const PaddingOracle: React.FC = () => {
  const addToolResult = useStore((state) => state.addToolResult);
  const [target, setTarget] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<TestResult | null>(null);

  const testPaddingOracle = async () => {
    if (!target || !ciphertext) return;

    setLoading(true);
    setResult(null);

    try {
      const details: string[] = [];
      let hasPaddingOracle = false;
      const blockSize = 16;

      details.push(`Testing target: ${target}`);
      details.push(`Ciphertext length: ${ciphertext.length} bytes`);
      details.push(`Assumed block size: ${blockSize} bytes`);

      const paddingTests = [
        { name: 'Valid padding', modifier: 0x00 },
        { name: 'Invalid padding (0x01)', modifier: 0x01 },
        { name: 'Invalid padding (0xFF)', modifier: 0xff },
        { name: 'Block boundary test', modifier: 0x10 },
      ];

      for (const test of paddingTests) {
        try {
          const modifiedCt = ciphertext + test.modifier.toString(16).padStart(2, '0');

          const response = await window.electronAPI.net.httpFetch(target, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({ data: modifiedCt }),
          });

          const responseText = String(response);

          if (
            responseText.toLowerCase().includes('padding') ||
            responseText.toLowerCase().includes('decrypt') ||
            responseText.toLowerCase().includes('invalid')
          ) {
            hasPaddingOracle = true;
            details.push(`✓ ${test.name}: Padding oracle detected in response`);
          } else {
            details.push(`✗ ${test.name}: No padding oracle indication`);
          }
        } catch (error) {
          const errorMsg = error instanceof Error ? error.message : 'Unknown error';
          if (
            errorMsg.toLowerCase().includes('padding') ||
            errorMsg.toLowerCase().includes('decrypt')
          ) {
            hasPaddingOracle = true;
            details.push(`✓ ${test.name}: Padding oracle detected in error`);
          } else {
            details.push(`✗ ${test.name}: Generic error response`);
          }
        }

        await new Promise((resolve) => setTimeout(resolve, 100));
      }

      if (hasPaddingOracle) {
        details.push('⚠️  VULNERABILITY: Padding oracle detected!');
        details.push('Attack possible: CBC mode decryption without key');
        details.push('Recommendation: Use authenticated encryption (GCM, CCM)');
      } else {
        details.push('✓ No obvious padding oracle vulnerability detected');
      }

      const testResult: TestResult = {
        blockSize,
        hasPaddingOracle,
        details,
      };

      setResult(testResult);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Padding Oracle',
        input: { target, ciphertext },
        output: testResult,
        success: true,
        timestamp: Date.now(),
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setResult({
        blockSize: 16,
        hasPaddingOracle: false,
        details: [`Error: ${errorMsg}`],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Padding Oracle Attack Tester"
      icon={<LockIcon />}
      description="Test for padding oracle vulnerabilities in cryptographic implementations"
    >
      <div className={styles.inputGroup}>
        <label className={styles.label}>Target URL</label>
        <input
          type="text"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="https://target.com/decrypt"
          className={styles.input}
        />
      </div>

      <div className={styles.inputGroup}>
        <label className={styles.label}>Ciphertext (hex)</label>
        <textarea
          value={ciphertext}
          onChange={(e) => setCiphertext(e.target.value)}
          placeholder="Enter encrypted data in hex format..."
          className={styles.textarea}
          rows={4}
        />
      </div>

      <div className={styles.buttonGroup}>
        <button
          onClick={testPaddingOracle}
          disabled={loading || !target || !ciphertext}
          className={styles.primaryBtn}
        >
          {loading ? (
            <>
              <LoadingIcon /> Testing...
            </>
          ) : (
            'Test Padding Oracle'
          )}
        </button>
      </div>

      {result && (
        <div className={styles.resultBox}>
          <span className={styles.resultTitle}>Padding Oracle Test Results</span>
          <div className={styles.resultItem}>
            <strong>Block Size:</strong> {result.blockSize} bytes
          </div>
          <div className={styles.resultItem}>
            <strong>Vulnerability Status:</strong>{' '}
            {result.hasPaddingOracle ? (
              <span className={styles.textError}>⚠️ VULNERABLE</span>
            ) : (
              <span className={styles.textSuccess}>✓ Not Vulnerable</span>
            )}
          </div>
          <div className={styles.resultItem}>
            <strong>Test Details:</strong>
            <pre className={styles.codeBlock}>{result.details.join('\n')}</pre>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default PaddingOracle;
