import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { ServerIcon } from '../common/Icons';

interface FingerprintResult {
  category: string;
  value: string;
  confidence: 'Low' | 'Medium' | 'High';
  source: string;
}

export const ServerFingerprinter: React.FC = () => {
  const [url, setUrl] = useState('');
  const [results, setResults] = useState<FingerprintResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [error, setError] = useState('');

  const fingerprint = async () => {
    if (!url.trim()) {
      setError('Please enter a URL');
      return;
    }

    try {
      setIsScanning(true);
      setError('');
      setResults([]);

      const targetUrl = url.startsWith('http') ? url : `https://${url}`;
      const response = await window.electronAPI.net.httpFetch(targetUrl, {
        method: 'GET',
        timeout: 10000,
      });

      if (!response.success) {
        setError(`Failed to fetch: ${response.error}`);
        setIsScanning(false);
        return;
      }

      const fingerprints: FingerprintResult[] = [];

      if (response.headers) {
        const server = response.headers.server || response.headers.Server;
        if (server) {
          fingerprints.push({
            category: 'Web Server',
            value: server,
            confidence: 'High',
            source: 'Server header',
          });

          if (server.toLowerCase().includes('apache')) {
            fingerprints.push({
              category: 'Technology',
              value: 'Apache HTTP Server',
              confidence: 'High',
              source: 'Server header analysis',
            });
          } else if (server.toLowerCase().includes('nginx')) {
            fingerprints.push({
              category: 'Technology',
              value: 'Nginx',
              confidence: 'High',
              source: 'Server header analysis',
            });
          } else if (server.toLowerCase().includes('iis')) {
            fingerprints.push({
              category: 'Technology',
              value: 'Microsoft IIS',
              confidence: 'High',
              source: 'Server header analysis',
            });
          } else if (server.toLowerCase().includes('cloudflare')) {
            fingerprints.push({
              category: 'CDN/WAF',
              value: 'Cloudflare',
              confidence: 'High',
              source: 'Server header',
            });
          }
        }

        const xPoweredBy = response.headers['x-powered-by'];
        if (xPoweredBy) {
          fingerprints.push({
            category: 'Backend Technology',
            value: xPoweredBy,
            confidence: 'High',
            source: 'X-Powered-By header',
          });

          if (xPoweredBy.toLowerCase().includes('php')) {
            fingerprints.push({
              category: 'Language',
              value: 'PHP',
              confidence: 'High',
              source: 'X-Powered-By header',
            });
          } else if (xPoweredBy.toLowerCase().includes('asp.net')) {
            fingerprints.push({
              category: 'Framework',
              value: 'ASP.NET',
              confidence: 'High',
              source: 'X-Powered-By header',
            });
          }
        }

        const xAspNetVersion = response.headers['x-aspnet-version'];
        if (xAspNetVersion) {
          fingerprints.push({
            category: 'Framework Version',
            value: `ASP.NET ${xAspNetVersion}`,
            confidence: 'High',
            source: 'X-AspNet-Version header',
          });
        }

        const xGenerator = response.headers['x-generator'];
        if (xGenerator) {
          fingerprints.push({
            category: 'CMS/Generator',
            value: xGenerator,
            confidence: 'High',
            source: 'X-Generator header',
          });
        }

        const via = response.headers.via || response.headers.Via;
        if (via) {
          fingerprints.push({
            category: 'Proxy/Cache',
            value: via,
            confidence: 'Medium',
            source: 'Via header',
          });
        }

        const cfRay = response.headers['cf-ray'];
        if (cfRay) {
          fingerprints.push({
            category: 'CDN/WAF',
            value: 'Cloudflare',
            confidence: 'High',
            source: 'CF-Ray header',
          });
        }

        const xAmzCfId = response.headers['x-amz-cf-id'];
        if (xAmzCfId) {
          fingerprints.push({
            category: 'CDN',
            value: 'Amazon CloudFront',
            confidence: 'High',
            source: 'X-Amz-Cf-Id header',
          });
        }
      }

      if (response.data) {
        const wpContent = response.data.match(/wp-content/i);
        if (wpContent) {
          fingerprints.push({
            category: 'CMS',
            value: 'WordPress',
            confidence: 'High',
            source: 'HTML content analysis (wp-content)',
          });
        }

        const joomla = response.data.match(/joomla/i);
        if (joomla) {
          fingerprints.push({
            category: 'CMS',
            value: 'Joomla',
            confidence: 'Medium',
            source: 'HTML content analysis',
          });
        }

        const drupal = response.data.match(/Drupal\.settings/i);
        if (drupal) {
          fingerprints.push({
            category: 'CMS',
            value: 'Drupal',
            confidence: 'High',
            source: 'HTML content analysis',
          });
        }

        const reactApp = response.data.match(/react/i) && response.data.match(/__REACT/i);
        if (reactApp) {
          fingerprints.push({
            category: 'Frontend Framework',
            value: 'React',
            confidence: 'Medium',
            source: 'HTML content analysis',
          });
        }

        const vueApp = response.data.match(/\[v-cloak\]|Vue\.component/i);
        if (vueApp) {
          fingerprints.push({
            category: 'Frontend Framework',
            value: 'Vue.js',
            confidence: 'Medium',
            source: 'HTML content analysis',
          });
        }

        const angularApp = response.data.match(/ng-app|ng-controller/i);
        if (angularApp) {
          fingerprints.push({
            category: 'Frontend Framework',
            value: 'Angular',
            confidence: 'Medium',
            source: 'HTML content analysis',
          });
        }

        const jquery = response.data.match(/jquery/i);
        if (jquery) {
          fingerprints.push({
            category: 'JavaScript Library',
            value: 'jQuery',
            confidence: 'Medium',
            source: 'HTML content analysis',
          });
        }
      }

      if (fingerprints.length === 0) {
        fingerprints.push({
          category: 'Status',
          value: 'No clear fingerprints detected',
          confidence: 'Low',
          source: 'Analysis complete',
        });
      }

      setResults(fingerprints);
    } catch (err) {
      setError(`Fingerprinting error: ${(err as Error).message}`);
    } finally {
      setIsScanning(false);
    }
  };

  const getConfidenceClass = (confidence: string) => {
    switch (confidence) {
      case 'High':
        return styles.badgeSuccess;
      case 'Medium':
        return styles.badgeWarning;
      case 'Low':
        return styles.badgeNeutral;
      default:
        return styles.badgeNeutral;
    }
  };

  return (
    <ToolWrapper
      title="Server Fingerprinter"
      icon={<ServerIcon />}
      description="Analyze server headers and detect technologies"
    >
      <div className={styles.inputGroup}>
        <label className={styles.label}>Target URL</label>
        <input
          type="text"
          className={styles.input}
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          placeholder="https://example.com"
          onKeyPress={(e) => e.key === 'Enter' && fingerprint()}
        />
      </div>

      <div className={styles.buttonGroup}>
        <button className={styles.primaryBtn} onClick={fingerprint} disabled={isScanning}>
          {isScanning ? 'Scanning...' : 'Fingerprint Server'}
        </button>
      </div>

      {error && <div className={styles.errorBox}>{error}</div>}

      {isScanning && (
        <div className={styles.loadingBox}>
          <div className={styles.spinner}></div>
          <span>Analyzing server...</span>
        </div>
      )}

      {results.length > 0 && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>
              Fingerprinting Results ({results.length} fingerprints detected)
            </span>
          </div>
          {results.map((result, idx) => (
            <div key={idx} className={styles.resultItem}>
              <div className={styles.resultRow}>
                <span className={styles.resultLabel}>{result.category}</span>
                <span className={`${styles.badge} ${getConfidenceClass(result.confidence)}`}>
                  {result.confidence}
                </span>
              </div>
              <div className={styles.resultValue}>{result.value}</div>
              <div
                style={{ color: 'var(--color-text-tertiary)', fontSize: '12px', marginTop: '4px' }}
              >
                Source: {result.source}
              </div>
            </div>
          ))}
        </div>
      )}
    </ToolWrapper>
  );
};

export default ServerFingerprinter;
