import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { ShieldIcon, LoadingIcon } from '../common/Icons';

const MassAssignment: React.FC = () => {
  const addToolResult = useStore((state) => state.addToolResult);
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<Array<{ param: string; status: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const commonParams = [
    'admin',
    'is_admin',
    'isAdmin',
    'role',
    'roles',
    'user_role',
    'is_verified',
    'verified',
    'active',
    'enabled',
    'status',
    'privileges',
    'permissions',
    'access_level',
    'level',
    'is_staff',
    'staff',
    'superuser',
    'is_superuser',
    'account_type',
    'user_type',
    'group',
    'groups',
    'credits',
    'balance',
    'coins',
    'points',
    'premium',
  ];

  const testMassAssignment = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ param: string; status: string }> = [];

      const baseline = await window.electronAPI.net.httpFetch(targetUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: 'test@example.com' }),
        timeout: 5000,
      });

      for (const param of commonParams) {
        try {
          const testData: Record<string, unknown> = {
            email: 'test@example.com',
            [param]: true,
          };

          const result = await window.electronAPI.net.httpFetch(targetUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(testData),
            timeout: 5000,
          });

          const isDifferent =
            result.status !== baseline.status ||
            JSON.stringify(result.data) !== JSON.stringify(baseline.data);

          found.push({
            param,
            status: isDifferent ? 'Accepted (Potential Vuln)' : 'Ignored',
          });
        } catch (err) {
          found.push({ param, status: 'Error' });
        }

        await new Promise((resolve) => setTimeout(resolve, 100));
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'Mass Assignment',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'Mass assignment test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="Mass Assignment Scanner"
      icon={<ShieldIcon />}
      description="Test endpoints for mass assignment vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Target URL (POST endpoint)</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/api/users"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testMassAssignment} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test Mass Assignment'
            )}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing mass assignment parameters...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultTitle}>Mass Assignment Results</div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span style={{ color: '#00ffaa', fontFamily: 'var(--font-mono)' }}>
                {result.param}
              </span>
              <span
                style={{
                  color: result.status.includes('Potential') ? '#ff4444' : '#888',
                  marginLeft: '10px',
                }}
              >
                {result.status}
              </span>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default MassAssignment;
