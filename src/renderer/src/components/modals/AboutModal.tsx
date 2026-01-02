import React from 'react';
import styles from './Modal.module.css';

interface AboutModalProps {
  onClose: () => void;
}

const AboutModal: React.FC<AboutModalProps> = ({ onClose }) => {
  return (
    <div className={styles.modalOverlay} onClick={onClose}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.modalHeader}>
          <h2>About Null IDE</h2>
          <button className={styles.closeBtn} onClick={onClose}>
            ×
          </button>
        </div>

        <div className={styles.modalBody}>
          <div className={styles.aboutContent}>
            <div className={styles.logo}>
              <span className={styles.logoIcon}>⚡</span>
              <h1>Null IDE</h1>
              <p className={styles.version}>Version 2.0.0</p>
            </div>

            <div className={styles.branding}>
              <p className={styles.tagline}>Dual-Mode Professional IDE</p>
              <p className={styles.subtitle}>Created by <strong>NullSec</strong></p>
            </div>

            <div className={styles.description}>
              <p>
                Null IDE is a privacy-focused, high-performance integrated development environment
                with dual modes: <strong>DeepZero</strong> for coding and <strong>GalaxyMind</strong> for
                security testing and developer utilities.
              </p>
              <div className={styles.featuresList}>
                <h4>✓ Monaco Editor with syntax highlighting</h4>
                <h4>✓ 25+ GalaxyMind tools (security & developer utilities)</h4>
                <h4>✓ Embedded DeepHat AI assistant</h4>
                <h4>✓ Privacy-focused (local-only storage)</h4>
                <h4>✓ Full keyboard shortcuts support</h4>
              </div>
            </div>

            <div className={styles.features}>
              <h3>⚡ DeepZero Mode</h3>
              <ul>
                <li>Monaco Editor (VS Code engine)</li>
                <li>Multi-tab file editing</li>
                <li>Integrated terminal</li>
                <li>DeepHat AI assistant</li>
              </ul>
              
              <h3>🌌 GalaxyMind Mode (25+ Tools)</h3>
              <ul>
                <li>🔐 Encoding: Base64, URL, Hash Generator, JWT Decoder, HTML Encoder</li>
                <li>🛠️ Developer: JSON, Regex, UUID, Timestamp, Password, Color, Markdown</li>
                <li>📝 Generators: Lorem Ipsum, QR Code, Secure Passwords</li>
                <li>🎨 Tools: CSS Minifier, Diff Viewer, Color Converter</li>
                <li>🌐 Network: API Tester, DNS Analyzer, Port Scanner</li>
                <li>🔒 Security: Header Analyzer, SQL/XSS Testing (Educational)</li>
              </ul>
              
              <h3>⌨️ Keyboard Shortcuts</h3>
              <ul>
                <li><strong>Ctrl+N</strong> - New File</li>
                <li><strong>Ctrl+S</strong> - Save File</li>
                <li><strong>Ctrl+W</strong> - Close Tab</li>
                <li><strong>Ctrl+Shift+W</strong> - Close All Tabs</li>
                <li><strong>Ctrl+Tab</strong> - Next Tab</li>
                <li><strong>Ctrl+Shift+Tab</strong> - Previous Tab</li>
                <li><strong>Ctrl+`</strong> - Toggle Terminal</li>
                <li><strong>Ctrl+B</strong> - Toggle Left Sidebar</li>
                <li><strong>Ctrl+,</strong> - Settings</li>
              </ul>
            </div>

            <div className={styles.tech}>
              <h3>🔧 Built With</h3>
              <ul>
                <li>Electron - Desktop application framework</li>
                <li>React - User interface library</li>
                <li>TypeScript - Type-safe development</li>
                <li>Monaco Editor - VS Code's editor core</li>
              </ul>
            </div>

            <div className={styles.privacy}>
              <h3>🔒 Privacy Commitment</h3>
              <p>
                <strong>Your code never leaves your machine.</strong> Null IDE is built with
                privacy as a core principle. All settings, files, and data are stored locally.
                No user tracking, no analytics, no telemetry.
              </p>
            </div>

            <div className={styles.disclaimer}>
              <p>
                <strong>Disclaimer:</strong> Null IDE's hacking tools are provided for educational
                and authorized security testing purposes only. Users are responsible for ensuring
                all usage complies with applicable laws and regulations.
              </p>
            </div>

            <div className={styles.copyright}>
              <p>© 2026 NullSec. All rights reserved.</p>
              <p className="text-secondary">
                Made with ❤️ by hackers, for hackers.
              </p>
            </div>
          </div>
        </div>

        <div className={styles.modalFooter}>
          <button className={styles.btnPrimary} onClick={onClose}>
            Close
          </button>
        </div>
      </div>
    </div>
  );
};

export default AboutModal;
