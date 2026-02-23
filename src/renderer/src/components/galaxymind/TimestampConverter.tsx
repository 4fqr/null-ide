import { useState, useEffect } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { ClockIcon, CopyIcon } from '../common/Icons';

export default function TimestampConverter() {
  const [timestamp, setTimestamp] = useState('');
  const [currentTime, setCurrentTime] = useState(Date.now());
  const [converted, setConverted] = useState<{
    unix: number;
    iso: string;
    utc: string;
    local: string;
  } | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    const interval = setInterval(() => {
      setCurrentTime(Date.now());
    }, 1000);
    return () => clearInterval(interval);
  }, []);

  const handleConvert = () => {
    setError('');
    setConverted(null);

    if (!timestamp.trim()) {
      setError('Please enter a timestamp');
      return;
    }

    try {
      let date: Date;

      const num = parseFloat(timestamp);
      if (!isNaN(num)) {
        date = new Date(num < 10000000000 ? num * 1000 : num);
      } else {
        date = new Date(timestamp);
      }

      if (isNaN(date.getTime())) {
        throw new Error('Invalid timestamp');
      }

      setConverted({
        unix: Math.floor(date.getTime() / 1000),
        iso: date.toISOString(),
        utc: date.toUTCString(),
        local: date.toLocaleString(),
      });
    } catch (err) {
      setError('Invalid timestamp format. Use Unix timestamp or ISO 8601 format.');
    }
  };

  const handleUseNow = () => {
    const now = Date.now();
    setTimestamp(Math.floor(now / 1000).toString());
  };

  const handleCopy = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const handleClear = () => {
    setTimestamp('');
    setConverted(null);
    setError('');
  };

  return (
    <ToolWrapper
      title="Timestamp Converter"
      icon={<ClockIcon />}
      description="Convert between Unix timestamps, ISO 8601, and human-readable date formats"
    >
      <div className={styles.section}>
        <div
          style={{
            padding: '1rem',
            background: 'var(--color-bg-tertiary)',
            borderRadius: '4px',
            marginBottom: '1rem',
            textAlign: 'center',
          }}
        >
          <div
            style={{
              fontSize: '0.75rem',
              color: 'var(--color-text-secondary)',
              marginBottom: '0.5rem',
            }}
          >
            Current Unix Timestamp
          </div>
          <div
            style={{
              fontFamily: 'var(--font-mono)',
              fontSize: '1.5rem',
              color: 'var(--color-text-primary)',
              fontWeight: 600,
            }}
          >
            {Math.floor(currentTime / 1000)}
          </div>
          <div
            style={{
              fontSize: '0.75rem',
              color: 'var(--color-text-tertiary)',
              marginTop: '0.25rem',
            }}
          >
            {new Date(currentTime).toLocaleString()}
          </div>
        </div>

        <div className={styles.inputGroup}>
          <div className={styles.label}>Timestamp to Convert</div>
          <input
            type="text"
            className={styles.input}
            value={timestamp}
            onChange={(e) => setTimestamp(e.target.value)}
            placeholder="Enter Unix timestamp or ISO 8601 date..."
          />
          <div
            style={{
              fontSize: '0.75rem',
              color: 'var(--color-text-tertiary)',
              marginTop: '0.25rem',
            }}
          >
            Examples: 1704153600, 2024-01-02T00:00:00Z
          </div>
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={handleConvert}>
            Convert
          </button>
          <button className={styles.secondaryBtn} onClick={handleUseNow}>
            Use Now
          </button>
          <button className={styles.secondaryBtn} onClick={handleClear}>
            Clear
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {converted && (
        <div className={styles.resultBox}>
          <div className={styles.resultTitle}>Converted Time</div>

          <div className={styles.resultItem}>
            <div className={styles.resultRow}>
              <div>
                <div
                  style={{
                    fontWeight: 600,
                    color: 'var(--color-text-primary)',
                    marginBottom: '0.25rem',
                  }}
                >
                  Unix Timestamp (seconds)
                </div>
                <div className={styles.resultValue}>{converted.unix}</div>
              </div>
              <button
                className={styles.copyBtn}
                onClick={() => handleCopy(converted.unix.toString())}
              >
                <CopyIcon />
              </button>
            </div>
          </div>

          <div className={styles.resultItem}>
            <div className={styles.resultRow}>
              <div>
                <div
                  style={{
                    fontWeight: 600,
                    color: 'var(--color-text-primary)',
                    marginBottom: '0.25rem',
                  }}
                >
                  ISO 8601
                </div>
                <div
                  style={{
                    fontFamily: 'var(--font-mono)',
                    fontSize: '0.875rem',
                    color: 'var(--color-text-secondary)',
                  }}
                >
                  {converted.iso}
                </div>
              </div>
              <button className={styles.copyBtn} onClick={() => handleCopy(converted.iso)}>
                <CopyIcon />
              </button>
            </div>
          </div>

          <div className={styles.resultItem}>
            <div className={styles.resultRow}>
              <div>
                <div
                  style={{
                    fontWeight: 600,
                    color: 'var(--color-text-primary)',
                    marginBottom: '0.25rem',
                  }}
                >
                  UTC
                </div>
                <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>
                  {converted.utc}
                </div>
              </div>
              <button className={styles.copyBtn} onClick={() => handleCopy(converted.utc)}>
                <CopyIcon />
              </button>
            </div>
          </div>

          <div className={styles.resultItem}>
            <div className={styles.resultRow}>
              <div>
                <div
                  style={{
                    fontWeight: 600,
                    color: 'var(--color-text-primary)',
                    marginBottom: '0.25rem',
                  }}
                >
                  Local Time
                </div>
                <div style={{ fontSize: '0.875rem', color: 'var(--color-text-secondary)' }}>
                  {converted.local}
                </div>
              </div>
              <button className={styles.copyBtn} onClick={() => handleCopy(converted.local)}>
                <CopyIcon />
              </button>
            </div>
          </div>
        </div>
      )}
    </ToolWrapper>
  );
}
