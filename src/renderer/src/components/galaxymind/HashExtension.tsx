import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { LockIcon, LoadingIcon } from '../common/Icons';

interface ExtensionResult {
  originalHash: string;
  extendedHash: string;
  payload: string;
  algorithms: string[];
  details: string[];
}

export const HashExtension: React.FC = () => {
  const { addToolResult } = useStore();
  const [originalHash, setOriginalHash] = useState('');
  const [knownData, setKnownData] = useState('');
  const [appendData, setAppendData] = useState('');
  const [secretLength, setSecretLength] = useState('16');
  const [algorithm, setAlgorithm] = useState('sha256');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ExtensionResult | null>(null);

  const performExtension = async () => {
    if (!originalHash || !knownData || !appendData) return;

    setLoading(true);
    setResult(null);

    try {
      const details: string[] = [];
      const keyLength = parseInt(secretLength);

      details.push(`Original Hash: ${originalHash}`);
      details.push(`Known Data: ${knownData}`);
      details.push(`Data to Append: ${appendData}`);
      details.push(`Secret Length: ${keyLength} bytes`);
      details.push(`Algorithm: ${algorithm.toUpperCase()}`);

      const originalLength = keyLength + knownData.length;
      const blockSize = algorithm === 'sha1' ? 64 : 64;
      const paddingLength = blockSize - ((originalLength + 9) % blockSize);

      details.push(`\nPadding Calculation:`);
      details.push(`Original message length: ${originalLength} bytes`);
      details.push(`Padding needed: ${paddingLength} bytes`);

      const padding = '\\x80' + '\\x00'.repeat(paddingLength);
      const lengthBits = (originalLength * 8).toString(16).padStart(16, '0');

      details.push(`\nPadding format: 0x80 + zeros + length`);
      details.push(`Length in bits: ${lengthBits}`);

      const extendedMessage = `${knownData}${padding}${lengthBits}${appendData}`;

      details.push(`\nExtended Message Construction:`);
      details.push(`Known Data + Padding + Length + New Data`);
      details.push(`Total length: ${extendedMessage.length} characters`);

      const extendedPayload = Buffer.from(appendData).toString('hex');
      const hashResult = await window.electronAPI.crypto.hash(
        algorithm as 'md5' | 'sha1' | 'sha256' | 'sha384' | 'sha512',
        extendedMessage
      );
      const extendedHash = hashResult.hash || '';

      details.push(`\nGenerated Extended Hash:`);
      details.push(extendedHash);

      details.push(`\nPayload to Send:`);
      details.push(`data=${knownData}${padding}${appendData}`);
      details.push(`signature=${extendedHash}`);

      details.push(`\n⚠️  Attack Vector:`);
      details.push(`If the server uses: HMAC(secret + data)`);
      details.push(`You can append data without knowing the secret`);
      details.push(`\n✓ Mitigation: Use proper HMAC implementation`);

      const extensionResult: ExtensionResult = {
        originalHash,
        extendedHash: typeof extendedHash === 'string' ? extendedHash : '',
        payload: extendedPayload,
        algorithms: ['sha1', 'sha256', 'md5'],
        details,
      };

      setResult(extensionResult);
      addToolResult({
        id: Date.now().toString(),
        toolName: 'Hash Extension',
        input: { originalHash, knownData, appendData, secretLength, algorithm },
        output: extensionResult,
        success: true,
        timestamp: Date.now(),
      });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      setResult({
        originalHash: '',
        extendedHash: '',
        payload: '',
        algorithms: [],
        details: [`Error: ${errorMsg}`],
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Hash Length Extension Attack"
      icon={<LockIcon />}
      description="Exploit hash length extension vulnerabilities in Merkle–Damgård construction hashes"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Original Hash:</label>
          <input
            type="text"
            value={originalHash}
            onChange={(e) => setOriginalHash(e.target.value)}
            placeholder="Original hash value"
            className={styles.input}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Known Data:</label>
          <input
            type="text"
            value={knownData}
            onChange={(e) => setKnownData(e.target.value)}
            placeholder="Data that was hashed (known)"
            className={styles.input}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Data to Append:</label>
          <input
            type="text"
            value={appendData}
            onChange={(e) => setAppendData(e.target.value)}
            placeholder="&admin=true"
            className={styles.input}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Secret Length (bytes):</label>
          <input
            type="number"
            value={secretLength}
            onChange={(e) => setSecretLength(e.target.value)}
            className={styles.input}
          />
        </div>

        <div className={styles.inputGroup}>
          <label className={styles.label}>Algorithm:</label>
          <select
            value={algorithm}
            onChange={(e) => setAlgorithm(e.target.value)}
            className={styles.select}
          >
            <option value="sha1">SHA-1</option>
            <option value="sha256">SHA-256</option>
            <option value="md5">MD5</option>
          </select>
        </div>

        <div className={styles.buttonGroup}>
          <button
            onClick={performExtension}
            disabled={loading || !originalHash || !knownData || !appendData}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Computing...
              </>
            ) : (
              'Perform Extension Attack'
            )}
          </button>
        </div>
      </div>

      {result && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Hash Extension Results</span>
          </div>
          <div className={styles.resultItem}>
            <strong>Extended Hash:</strong>
            <pre className={styles.codeBlock}>{result.extendedHash}</pre>
          </div>
          <div className={styles.resultItem}>
            <strong>Details:</strong>
            <pre className={styles.codeBlock}>{result.details.join('\n')}</pre>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
};

export default HashExtension;
