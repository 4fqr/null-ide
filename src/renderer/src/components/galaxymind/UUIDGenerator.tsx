import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { IdIcon, CopyIcon } from '../common/Icons';

export default function UUIDGenerator() {
  const [uuids, setUuids] = useState<string[]>([]);
  const [count, setCount] = useState(5);

  const generateUUIDs = () => {
    const newUuids: string[] = [];
    for (let i = 0; i < count; i++) {
      newUuids.push(crypto.randomUUID());
    }
    setUuids(newUuids);
  };

  const handleCopy = (uuid: string) => {
    navigator.clipboard.writeText(uuid);
  };

  const handleCopyAll = () => {
    navigator.clipboard.writeText(uuids.join('\n'));
  };

  const handleClear = () => {
    setUuids([]);
  };

  return (
    <ToolWrapper
      title="UUID Generator"
      icon={<IdIcon />}
      description="Generate unique identifiers for your applications"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Number of UUIDs</label>
          <input
            type="number"
            className={styles.input}
            value={count}
            onChange={(e) => setCount(Math.max(1, Math.min(100, parseInt(e.target.value) || 1)))}
            min="1"
            max="100"
          />
          <div
            style={{
              fontSize: '0.75rem',
              color: 'var(--color-text-tertiary)',
              marginTop: '0.25rem',
            }}
          >
            Generate 1-100 UUIDs at once
          </div>
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={generateUUIDs}>
            Generate UUIDs
          </button>
          {uuids.length > 0 && (
            <>
              <button className={styles.secondaryBtn} onClick={handleCopyAll}>
                <CopyIcon /> Copy All
              </button>
              <button className={styles.secondaryBtn} onClick={handleClear}>
                Clear
              </button>
            </>
          )}
        </div>
      </div>

      {uuids.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Generated UUIDs ({uuids.length})</span>
          </div>
          {uuids.map((uuid, index) => (
            <div key={index} className={styles.resultItem}>
              <div className={styles.resultRow}>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.875rem',
                    color: 'var(--color-text-primary)',
                    flex: 1,
                  }}
                >
                  {uuid}
                </div>
                <button className={styles.copyBtn} onClick={() => handleCopy(uuid)}>
                  <CopyIcon />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
}
