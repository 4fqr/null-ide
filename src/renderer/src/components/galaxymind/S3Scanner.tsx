import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';
import { DatabaseIcon, LoadingIcon } from '../common/Icons';
import ToolWrapper from './ToolWrapper';

const S3Scanner: React.FC = () => {
  const { addToolResult } = useStore();
  const [bucketName, setBucketName] = useState('');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testS3 = async () => {
    if (!bucketName.trim()) {
      setError('Bucket name is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ test: string; result: string }> = [];
      const regions = ['us-east-1', 's3', 'eu-west-1', 'ap-southeast-1'];

      for (const region of regions) {
        const url =
          region === 's3'
            ? `https://${bucketName}.s3.amazonaws.com`
            : `https://${bucketName}.s3.${region}.amazonaws.com`;

        try {
          const result = await window.electronAPI.net.httpFetch(url, {
            method: 'GET',
            timeout: 5000,
          });

          if (result.status === 200) {
            found.push({ test: `Bucket (${region})`, result: 'PUBLIC READ!' });
          } else if (result.status === 403) {
            found.push({ test: `Bucket (${region})`, result: 'Exists (Private)' });
          } else if (result.status === 404) {
            found.push({ test: `Bucket (${region})`, result: 'Not Found' });
          }
        } catch {
          found.push({ test: `Bucket (${region})`, result: 'Error' });
        }

        await new Promise((resolve) => setTimeout(resolve, 300));
      }

      const writeUrl = `https://${bucketName}.s3.amazonaws.com/test.txt`;
      try {
        await window.electronAPI.net.httpFetch(writeUrl, {
          method: 'PUT',
          body: 'test',
          timeout: 3000,
        });
        found.push({ test: 'Write Access', result: 'PUBLIC WRITE!' });
      } catch {
        found.push({ test: 'Write Access', result: 'Blocked' });
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'S3 Scanner',
        timestamp: Date.now(),
        input: { bucketName },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'S3 scan failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="S3 Bucket Scanner"
      icon={<DatabaseIcon />}
      description="Test AWS S3 bucket permissions and access controls"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>S3 Bucket Name</label>
          <input
            type="text"
            className={styles.input}
            placeholder="my-bucket-name"
            value={bucketName}
            onChange={(e) => setBucketName(e.target.value)}
          />
        </div>

        <button className={styles.primaryBtn} onClick={testS3} disabled={loading}>
          {loading ? (
            <>
              <LoadingIcon /> Scanning...
            </>
          ) : (
            'Scan S3 Bucket'
          )}
        </button>
      </div>

      {error && (
        <div className={styles.errorBox}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing S3 bucket permissions...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultTitle}>S3 Bucket Test Results</div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.test}
              </span>
              <span
                style={{
                  color: result.result.includes('PUBLIC') ? '#ff4444' : '#888',
                  marginLeft: '10px',
                }}
              >
                {result.result}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default S3Scanner;
