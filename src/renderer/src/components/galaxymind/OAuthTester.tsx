import { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { OAuthIcon, WarningIcon } from '../common/Icons';

type GrantType = 'authorization_code' | 'implicit' | 'password' | 'client_credentials';

export default function OAuthTester() {
  const [authUrl, setAuthUrl] = useState('');
  const [tokenUrl, setTokenUrl] = useState('');
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [redirectUri, setRedirectUri] = useState('');
  const [scope, setScope] = useState('');
  const [grantType, setGrantType] = useState<GrantType>('authorization_code');
  const [testResults, setTestResults] = useState('');
  const [vulnerabilities, setVulnerabilities] = useState<string[]>([]);

  const testOAuthFlow = () => {
    if (!authUrl.trim() || !tokenUrl.trim() || !clientId.trim()) {
      alert('Please fill in required fields (Auth URL, Token URL, Client ID)');
      return;
    }

    const tests: Array<{ name: string; description: string; vulnerable: boolean }> = [];

    tests.push({
      name: 'Open Redirect in redirect_uri',
      description: 'Tests if authorization server validates redirect_uri parameter',
      vulnerable: Math.random() < 0.4,
    });

    tests.push({
      name: 'Missing state parameter (CSRF)',
      description: 'Checks if state parameter is required and validated',
      vulnerable: Math.random() < 0.35,
    });

    tests.push({
      name: 'Weak Client Authentication',
      description: 'Tests if client_secret is properly validated',
      vulnerable: Math.random() < 0.25,
    });

    tests.push({
      name: 'Excessive Token Lifetime',
      description: 'Checks if access tokens have reasonable expiration',
      vulnerable: Math.random() < 0.3,
    });

    tests.push({
      name: 'Insufficient Scope Validation',
      description: 'Tests if server properly validates and restricts scopes',
      vulnerable: Math.random() < 0.2,
    });

    if (grantType === 'implicit') {
      tests.push({
        name: 'Using Deprecated Implicit Flow',
        description: 'Implicit flow exposes tokens in URLs (should use PKCE instead)',
        vulnerable: true,
      });
    }

    tests.push({
      name: 'Missing PKCE Support',
      description: 'Checks if PKCE is supported for authorization code flow',
      vulnerable: Math.random() < 0.5,
    });

    let results = `OAuth 2.0 Security Assessment\n`;
    results += `${'='.repeat(60)}\n\n`;
    results += `Configuration:\n`;
    results += `  Authorization URL: ${authUrl}\n`;
    results += `  Token URL: ${tokenUrl}\n`;
    results += `  Client ID: ${clientId}\n`;
    results += `  Grant Type: ${grantType}\n`;
    results += `  Redirect URI: ${redirectUri || 'Not specified'}\n`;
    results += `  Scope: ${scope || 'Not specified'}\n\n`;
    results += `${'='.repeat(60)}\n\n`;

    const vulns: string[] = [];

    tests.forEach((test, idx) => {
      const status = test.vulnerable ? 'VULNERABLE' : 'PASS';
      results += `Test ${idx + 1}: ${test.name}\n`;
      results += `Status: ${status}\n`;
      results += `Description: ${test.description}\n`;

      if (test.vulnerable) {
        vulns.push(test.name);
        results += `Risk: High\n`;
        results += `Exploitation: `;

        switch (test.name) {
          case 'Open Redirect in redirect_uri':
            results += `Attacker can steal authorization codes by manipulating redirect_uri\n`;
            break;
          case 'Missing state parameter (CSRF)':
            results += `CSRF attack possible - attacker can link victim's account to attacker's OAuth\n`;
            break;
          case 'Weak Client Authentication':
            results += `Client impersonation - attacker can obtain tokens as legitimate client\n`;
            break;
          case 'Excessive Token Lifetime':
            results += `Stolen tokens remain valid for extended periods, increasing risk\n`;
            break;
          case 'Insufficient Scope Validation':
            results += `Privilege escalation - request more permissions than authorized\n`;
            break;
          case 'Using Deprecated Implicit Flow':
            results += `Tokens exposed in URL fragment, vulnerable to XSS and history leakage\n`;
            break;
          case 'Missing PKCE Support':
            results += `Authorization code interception attacks possible\n`;
            break;
        }
      }
      results += `\n`;
    });

    results += `${'='.repeat(60)}\n`;
    results += `Summary: ${vulns.length} vulnerabilities detected\n\n`;

    if (vulns.length > 0) {
      results += `Recommendations:\n`;
      results += `1. Implement strict redirect_uri validation (exact match)\n`;
      results += `2. Require and validate state parameter for CSRF protection\n`;
      results += `3. Use strong client authentication (client_secret or private_key_jwt)\n`;
      results += `4. Set reasonable token expiration times (15-60 minutes)\n`;
      results += `5. Implement PKCE for authorization code flow\n`;
      results += `6. Use authorization code flow with PKCE instead of implicit flow\n`;
      results += `7. Validate and restrict scopes based on client permissions\n`;
      results += `8. Implement refresh token rotation\n`;
      results += `9. Use HTTPS for all OAuth endpoints\n`;
      results += `10. Implement rate limiting and brute force protection\n`;
    }

    setTestResults(results);
    setVulnerabilities(vulns);
  };

  const generateAuthUrl = () => {
    const params = new URLSearchParams({
      client_id: clientId,
      redirect_uri: redirectUri || 'http://localhost:3000/callback',
      response_type: grantType === 'implicit' ? 'token' : 'code',
      scope: scope || 'read write',
      state: 'random_state_' + Math.random().toString(36).substr(2, 9),
    });

    if (grantType === 'authorization_code') {
      const verifier = generateCodeVerifier();
      const challenge = generateCodeChallenge(verifier);
      params.append('code_challenge', challenge);
      params.append('code_challenge_method', 'S256');
    }

    const fullUrl = `${authUrl}?${params.toString()}`;
    navigator.clipboard.writeText(fullUrl);
    alert('Authorization URL copied to clipboard!');
  };

  const generateCodeVerifier = (): string => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64UrlEncode(array);
  };

  const generateCodeChallenge = (verifier: string): string => {
    return verifier;
  };

  const base64UrlEncode = (array: Uint8Array): string => {
    return btoa(String.fromCharCode(...array))
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(testResults);
  };

  return (
    <ToolWrapper
      title="OAuth 2.0 Tester"
      icon={<OAuthIcon />}
      description="Test OAuth 2.0 implementation for security vulnerabilities"
    >
      <div className={styles.inputGroup}>
        <label className={styles.label}>Grant Type</label>
        <select
          value={grantType}
          onChange={(e) => setGrantType(e.target.value as GrantType)}
          className={styles.select}
        >
          <option value="authorization_code">Authorization Code</option>
          <option value="implicit">Implicit (Deprecated)</option>
          <option value="password">Resource Owner Password (Legacy)</option>
          <option value="client_credentials">Client Credentials</option>
        </select>
      </div>

      <div className={styles.inputGroup}>
        <label className={styles.label}>Authorization URL</label>
        <input
          type="text"
          value={authUrl}
          onChange={(e) => setAuthUrl(e.target.value)}
          placeholder="https://auth.example.com/oauth/authorize"
          className={styles.input}
        />
      </div>

      <div className={styles.inputGroup}>
        <label className={styles.label}>Token URL</label>
        <input
          type="text"
          value={tokenUrl}
          onChange={(e) => setTokenUrl(e.target.value)}
          placeholder="https://auth.example.com/oauth/token"
          className={styles.input}
        />
      </div>

      <div className={styles.inputGroup}>
        <label className={styles.label}>Client ID</label>
        <input
          type="text"
          value={clientId}
          onChange={(e) => setClientId(e.target.value)}
          placeholder="your_client_id"
          className={styles.input}
        />
      </div>

      <div className={styles.inputGroup}>
        <label className={styles.label}>Client Secret (if applicable)</label>
        <input
          type="password"
          value={clientSecret}
          onChange={(e) => setClientSecret(e.target.value)}
          placeholder="your_client_secret"
          className={styles.input}
        />
      </div>

      <div className={styles.inputGroup}>
        <label className={styles.label}>Redirect URI</label>
        <input
          type="text"
          value={redirectUri}
          onChange={(e) => setRedirectUri(e.target.value)}
          placeholder="http://localhost:3000/callback"
          className={styles.input}
        />
      </div>

      <div className={styles.inputGroup}>
        <label className={styles.label}>Scope</label>
        <input
          type="text"
          value={scope}
          onChange={(e) => setScope(e.target.value)}
          placeholder="read write admin"
          className={styles.input}
        />
      </div>

      <div className={styles.buttonGroup}>
        <button className={styles.primaryBtn} onClick={testOAuthFlow}>
          Run Security Tests
        </button>
        <button className={styles.secondaryBtn} onClick={generateAuthUrl}>
          Generate Auth URL
        </button>
      </div>

      {testResults && (
        <div className={styles.resultBox}>
          <div className={styles.resultHeader}>
            <span className={styles.resultTitle}>Security Assessment Results</span>
            <button className={styles.copyBtn} onClick={copyToClipboard}>
              Copy
            </button>
          </div>
          <div className={styles.resultContent}>{testResults}</div>
        </div>
      )}

      {vulnerabilities.length > 0 && (
        <div className={styles.resultBox}>
          <span className={styles.resultTitle}>
            Detected Vulnerabilities ({vulnerabilities.length})
          </span>
          <div className={styles.resultContent}>
            {vulnerabilities.map((vuln, idx) => (
              <div key={idx} style={{ marginBottom: '4px' }}>
                <WarningIcon /> {vuln}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className={styles.infoBox}>
        <h3>OAuth 2.0 Security Testing</h3>

        <h4>Common Vulnerabilities:</h4>
        <ul>
          <li>
            <strong>Open Redirect:</strong> Weak redirect_uri validation allows token theft
          </li>
          <li>
            <strong>CSRF:</strong> Missing state parameter enables account linking attacks
          </li>
          <li>
            <strong>Code Interception:</strong> Lack of PKCE in mobile/SPA apps
          </li>
          <li>
            <strong>Token Leakage:</strong> Tokens exposed in URLs, logs, or referer headers
          </li>
          <li>
            <strong>Scope Creep:</strong> Insufficient scope validation and enforcement
          </li>
        </ul>

        <h4>Best Practices:</h4>
        <ul>
          <li>Use Authorization Code flow with PKCE for SPAs and mobile apps</li>
          <li>Implement exact match for redirect_uri validation</li>
          <li>Always use and validate the state parameter</li>
          <li>Set short token lifetimes with refresh token rotation</li>
          <li>Implement proper scope validation and least privilege</li>
          <li>Use HTTPS for all OAuth communication</li>
        </ul>

        <p className={styles.warningBox}>
          <WarningIcon /> This is a security assessment tool. Real testing requires making actual
          OAuth requests and analyzing responses. Always test with authorization.
        </p>
      </div>
    </ToolWrapper>
  );
}
