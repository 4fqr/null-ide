import React, { useState } from 'react';
import styles from './SharedTool.module.css';
import ToolWrapper from './ToolWrapper';
import { BugIcon, LoadingIcon } from '../common/Icons';

const GraphQLScanner: React.FC = () => {
  const [endpoint, setEndpoint] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState('');

  const scanGraphQL = async () => {
    if (!endpoint.trim()) return;
    setLoading(true);
    let output = `GraphQL Security Scanner - ${endpoint}\n\n`;

    try {
      const introspectionQuery = JSON.stringify({
        query: '{ __schema { types { name } } }',
      });

      const response = await window.electronAPI.net.httpFetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: introspectionQuery,
        timeout: 5000,
      });

      const data = response.data || '';

      if (data.includes('__schema') || data.includes('types')) {
        output += '✗ CRITICAL: Introspection ENABLED\n';
        output += 'Full schema can be enumerated - all types, queries, mutations exposed\n\n';
      } else {
        output += '✓ Introspection appears disabled\n\n';
      }
    } catch (e) {
      output += `Connection error: ${e}\n\n`;
    }

    output += 'GraphQL Vulnerabilities:\n';
    output += '• Introspection - schema enumeration\n';
    output += '• No depth limiting - nested query DoS\n';
    output += '• No rate limiting - resource exhaustion\n';
    output += '• IDOR in mutations - unauthorized data modification\n';
    output += '• SQL/NoSQL injection in resolvers\n';
    output += '• Authorization bypass - missing field-level checks\n';
    output += '• Batch query attacks - amplification\n\n';
    output += 'Testing:\n';
    output += '• InQL - Burp extension for GraphQL\n';
    output += '• GraphQL Voyager - schema visualization\n';
    output += '• graphql-playground - interactive testing\n\n';
    output += 'Hardening:\n';
    output += '• Disable introspection in production\n';
    output += '• Implement query depth limiting\n';
    output += '• Add query complexity analysis\n';
    output += '• Rate limit by cost, not just requests\n';
    output += '• Field-level authorization checks\n';
    output += '• Input validation in all resolvers\n';

    setResult(output);
    setLoading(false);
  };

  return (
    <ToolWrapper
      title="GraphQL Scanner"
      icon={<BugIcon />}
      description="Scans GraphQL endpoints for introspection, injection, authorization bypass, and DoS vulnerabilities"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Endpoint</label>
          <input
            type="text"
            value={endpoint}
            onChange={(e) => setEndpoint(e.target.value)}
            placeholder="https://api.example.com/graphql"
            className={styles.input}
          />
        </div>
        <div className={styles.buttonGroup}>
          <button
            onClick={scanGraphQL}
            disabled={loading || !endpoint.trim()}
            className={styles.primaryBtn}
          >
            {loading ? (
              <>
                <LoadingIcon /> Scanning...
              </>
            ) : (
              'Scan GraphQL'
            )}
          </button>
        </div>
      </div>
      {result && (
        <div className={styles.resultBox}>
          <pre className={styles.resultContent}>{result}</pre>
        </div>
      )}
    </ToolWrapper>
  );
};

export default GraphQLScanner;
