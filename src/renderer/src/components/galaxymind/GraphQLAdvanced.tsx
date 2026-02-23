import React, { useState } from 'react';
import { useStore } from '../../store/store';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { NetworkIcon, LoadingIcon } from '../common/Icons';

const GraphQLAdvanced: React.FC = () => {
  const { addToolResult } = useStore();
  const [targetUrl, setTargetUrl] = useState('');
  const [results, setResults] = useState<Array<{ test: string; result: string }>>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const testGraphQL = async () => {
    if (!targetUrl.trim()) {
      setError('Target URL is required');
      return;
    }

    setLoading(true);
    setError(null);
    setResults([]);

    try {
      const found: Array<{ test: string; result: string }> = [];

      const introspectionQuery = { query: '{ __schema { types { name } } }' };
      try {
        const result = await window.electronAPI.net.httpFetch(targetUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(introspectionQuery),
          timeout: 5000,
        });

        const enabled =
          result.success && (result.data?.includes('__schema') || result.data?.includes('types'));
        found.push({ test: 'Introspection', result: enabled ? 'ENABLED (Vuln)' : 'Disabled' });
      } catch {
        found.push({ test: 'Introspection', result: 'Error' });
      }

      const fieldSuggestion = { query: '{ __type(name: "Query") { fields { name } } }' };
      try {
        const result = await window.electronAPI.net.httpFetch(targetUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(fieldSuggestion),
          timeout: 5000,
        });

        const enabled = result.success && result.data?.includes('fields');
        found.push({ test: 'Field Suggestions', result: enabled ? 'Available' : 'Blocked' });
      } catch {
        found.push({ test: 'Field Suggestions', result: 'Error' });
      }

      const batchQuery = [{ query: '{ __typename }' }, { query: '{ __typename }' }];
      try {
        const result = await window.electronAPI.net.httpFetch(targetUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(batchQuery),
          timeout: 5000,
        });

        const allowed = result.status === 200;
        found.push({ test: 'Batch Queries', result: allowed ? 'ALLOWED (DoS Risk)' : 'Blocked' });
      } catch {
        found.push({ test: 'Batch Queries', result: 'Blocked' });
      }

      const deepQuery = { query: '{ a { b { c { d { e { f { g { h } } } } } } } }' };
      try {
        const result = await window.electronAPI.net.httpFetch(targetUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(deepQuery),
          timeout: 5000,
        });

        const blocked = result.status === 400 || (result.success && result.data?.includes('depth'));
        found.push({ test: 'Depth Limiting', result: blocked ? 'Protected' : 'NOT PROTECTED' });
      } catch {
        found.push({ test: 'Depth Limiting', result: 'Protected' });
      }

      const costlyQuery = { query: '{ __schema { types { name fields { name } } } }' };
      try {
        await window.electronAPI.net.httpFetch(targetUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(costlyQuery),
          timeout: 5000,
        });

        found.push({ test: 'Cost Analysis', result: 'Unknown' });
      } catch {
        found.push({ test: 'Cost Analysis', result: 'Possibly Protected' });
      }

      setResults(found);

      addToolResult({
        id: Date.now().toString(),
        toolName: 'GraphQL Advanced',
        timestamp: Date.now(),
        input: { targetUrl },
        output: found,
        success: true,
      });
    } catch (err: unknown) {
      const message = err instanceof Error ? err.message : 'GraphQL test failed';
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <ToolWrapper
      title="GraphQL Advanced Scanner"
      icon={<NetworkIcon />}
      description="Test GraphQL endpoints for security misconfigurations"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>GraphQL Endpoint</label>
          <input
            type="text"
            className={styles.input}
            placeholder="https://example.com/graphql"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={testGraphQL} disabled={loading}>
            {loading ? (
              <>
                <LoadingIcon /> Testing...
              </>
            ) : (
              'Test GraphQL'
            )}
          </button>
        </div>
      </div>

      {error && (
        <div className={styles.errorBox}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {loading && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Testing GraphQL security...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <h3 className={styles.resultTitle}>GraphQL Security Tests</h3>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <span className={styles.code}>{result.test}</span>
              <span
                className={
                  result.result.includes('Vuln') ||
                  result.result.includes('ALLOWED') ||
                  result.result.includes('NOT PROTECTED')
                    ? styles.textError
                    : styles.resultContent
                }
                style={{ marginLeft: '10px' }}
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

export default GraphQLAdvanced;
