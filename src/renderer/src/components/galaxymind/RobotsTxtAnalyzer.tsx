import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { FileIcon } from '../common/Icons';

interface RobotsEntry {
  line: string;
  type: 'Disallow' | 'Allow' | 'Sitemap' | 'User-agent' | 'Crawl-delay' | 'Other';
  value: string;
  interesting: boolean;
  reason: string;
}

export const RobotsTxtAnalyzer: React.FC = () => {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<RobotsEntry[]>([]);
  const [rawContent, setRawContent] = useState('');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [error, setError] = useState('');

  const analyze = async () => {
    if (!url.trim()) {
      setError('Please enter a domain');
      return;
    }

    try {
      setIsAnalyzing(true);
      setError('');
      setResults([]);
      setRawContent('');

      let baseUrl = url.trim();
      if (!baseUrl.startsWith('http')) {
        baseUrl = `https://${baseUrl}`;
      }

      const urlObj = new URL(baseUrl);
      const robotsUrl = `${urlObj.protocol}//${urlObj.host}/robots.txt`;

      const response = await window.electronAPI.net.httpFetch(robotsUrl, {
        method: 'GET',
        timeout: 10000,
      });

      if (!response.success || !response.data) {
        setError('robots.txt not found or inaccessible');
        setIsAnalyzing(false);
        return;
      }

      setRawContent(response.data);

      const lines = response.data.split('\n');
      const entries: RobotsEntry[] = [];

      const interestingPaths = [
        'admin',
        'login',
        'dashboard',
        'api',
        'config',
        'backup',
        'db',
        'sql',
        'private',
        'secret',
        'hidden',
        'internal',
        'test',
        'dev',
        'staging',
        'uploads',
        '.env',
        '.git',
        'wp-admin',
        'phpinfo',
      ];

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#')) continue;

        const [directive, ...valueParts] = trimmed.split(':');
        const value = valueParts.join(':').trim();
        const directiveLower = directive.toLowerCase().trim();

        let type: 'Disallow' | 'Allow' | 'Sitemap' | 'User-agent' | 'Crawl-delay' | 'Other' =
          'Other';
        let interesting = false;
        let reason = '';

        if (directiveLower === 'disallow') {
          type = 'Disallow';
          const valueLower = value.toLowerCase();
          interesting = interestingPaths.some((path) => valueLower.includes(path));
          if (interesting) {
            reason = 'Potentially sensitive path blocked from crawlers';
          }
          if (value === '/' || value === '/*') {
            interesting = true;
            reason = 'Site completely blocked from crawlers';
          }
        } else if (directiveLower === 'allow') {
          type = 'Allow';
        } else if (directiveLower === 'sitemap') {
          type = 'Sitemap';
          interesting = true;
          reason = 'Sitemap location revealed - check for indexed paths';
        } else if (directiveLower === 'user-agent') {
          type = 'User-agent';
        } else if (directiveLower === 'crawl-delay') {
          type = 'Crawl-delay';
        }

        entries.push({
          line: trimmed,
          type,
          value,
          interesting,
          reason,
        });
      }

      setResults(entries);
    } catch (err) {
      setError(`Analysis error: ${(err as Error).message}`);
    } finally {
      setIsAnalyzing(false);
    }
  };

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'Disallow':
        return '#ff3366';
      case 'Allow':
        return '#00ff41';
      case 'Sitemap':
        return '#00aaff';
      case 'User-agent':
        return '#ffaa00';
      default:
        return '#888';
    }
  };

  return (
    <ToolWrapper
      title="robots.txt Analyzer"
      icon={<FileIcon />}
      description="Analyze robots.txt files for interesting paths and security insights"
    >
      <div className={styles.section}>
        <div className={styles.inputGroup}>
          <label className={styles.label}>Domain URL</label>
          <input
            type="text"
            className={styles.input}
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="example.com or https://example.com"
            onKeyPress={(e) => e.key === 'Enter' && analyze()}
          />
        </div>

        <div className={styles.buttonGroup}>
          <button className={styles.primaryBtn} onClick={analyze} disabled={isAnalyzing}>
            {isAnalyzing ? 'Analyzing...' : 'Analyze robots.txt'}
          </button>
        </div>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultTitle}>
            Analysis Results ({results.filter((r) => r.interesting).length} interesting paths found)
          </div>

          {results.filter((r) => r.interesting).length > 0 && (
            <div style={{ marginBottom: '20px' }}>
              <div className={styles.sectionTitle}>Interesting Findings</div>
              {results
                .filter((r) => r.interesting)
                .map((result, idx) => (
                  <div
                    key={idx}
                    className={styles.resultItem}
                    style={{ borderLeft: '3px solid #ff3366' }}
                  >
                    <div
                      style={{
                        fontWeight: 600,
                        color: getTypeColor(result.type),
                        marginBottom: '5px',
                      }}
                    >
                      {result.type}: {result.value}
                    </div>
                    <div style={{ color: 'var(--color-text-secondary)', fontSize: '13px' }}>
                      {result.reason}
                    </div>
                  </div>
                ))}
            </div>
          )}

          <div className={styles.sectionTitle}>All Entries</div>
          {results.map((result, idx) => (
            <div
              key={idx}
              className={styles.resultItem}
              style={{ borderLeft: result.interesting ? '2px solid #ff3366' : undefined }}
            >
              <span
                style={{ color: getTypeColor(result.type), fontWeight: 600, marginRight: '10px' }}
              >
                {result.type}:
              </span>
              <span style={{ color: 'var(--color-text-secondary)' }}>{result.value}</span>
            </div>
          ))}

          {rawContent && (
            <div style={{ marginTop: '20px' }}>
              <div className={styles.sectionTitle}>Raw Content</div>
              <pre className={styles.codeBlock} style={{ maxHeight: '300px' }}>
                {rawContent}
              </pre>
            </div>
          )}
        </div>
      )}
    </ToolWrapper>
  );
};

export default RobotsTxtAnalyzer;
