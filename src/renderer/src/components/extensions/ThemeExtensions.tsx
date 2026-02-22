import { useState, useEffect } from 'react';
import { ThemeManager, Theme } from '../../utils/themeManager';
import styles from './ThemeExtensions.module.css';

export default function ThemeExtensions() {
  const [themes, setThemes] = useState<Theme[]>([]);
  const [currentTheme, setCurrentTheme] = useState('');
  const [showInstall, setShowInstall] = useState(false);
  const [themeCSS, setThemeCSS] = useState('');
  const [themeName, setThemeName] = useState('');
  const [themeId, setThemeId] = useState('');
  const [themeDesc, setThemeDesc] = useState('');
  const [themeAuthor, setThemeAuthor] = useState('');

  
  useEffect(() => {
    if (showInstall && !themeCSS) {
      loadThemeTemplate();
    }
  }, [showInstall]);

  useEffect(() => {
    loadThemes();
  }, []);

  const loadThemes = () => {
    setThemes(ThemeManager.getAllThemes());
    setCurrentTheme(ThemeManager.getCurrentTheme());
  };

  const applyTheme = (themeId: string) => {
    ThemeManager.setTheme(themeId);
    setCurrentTheme(themeId);
  };

  const installTheme = () => {
    if (!themeId || !themeName || !themeCSS) {
      alert('Please fill in all required fields');
      return;
    }

    const success = ThemeManager.installTheme(themeCSS, {
      id: themeId,
      name: themeName,
      description: themeDesc || 'Custom theme',
      author: themeAuthor || 'Unknown',
      version: '1.0.0',
    });

    if (success) {
      alert('Theme installed successfully!');
      setShowInstall(false);
      loadThemes();
      
      setThemeCSS('');
      setThemeName('');
      setThemeId('');
      setThemeDesc('');
      setThemeAuthor('');
    } else {
      alert('Failed to install theme. Check console for errors.');
    }
  };

  const uninstallTheme = (themeId: string) => {
    if (confirm(`Are you sure you want to uninstall this theme?`)) {
      ThemeManager.uninstallTheme(themeId);
      loadThemes();
    }
  };

  const exportTheme = (themeId: string) => {
    const exported = ThemeManager.exportTheme(themeId);
    if (exported) {
      const blob = new Blob([exported], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${themeId}-theme.json`;
      a.click();
      URL.revokeObjectURL(url);
    }
  };

  const loadThemeTemplate = () => {
    const template = `:root[data-theme="my-theme"] {
  /* Background Colors */
  --color-bg-primary: #050505;
  --color-bg-secondary: #0a0a0a;
  --color-bg-tertiary: #0f0f0f;
  --color-bg-elevated: #141414;
  --color-bg-hover: #1a1a1a;
  
  /* Accent Color */
  --color-accent: #00d9ff;
  --color-accent-dim: #00b0d9;
  
  /* Text Colors */
  --color-text-primary: #f0f0f0;
  --color-text-secondary: #a0a0a0;
  --color-text-tertiary: #707070;
  
  /* Border Colors */
  --color-border: #252525;
  --color-border-subtle: #1a1a1a;
  
  /* Status Colors */
  --color-success: #00ff88;
  --color-warning: #ffaa00;
  --color-error: #ff3366;
}`;
    setThemeCSS(template);
  };

  return (
    <div className={styles.themeExtensions}>
      <div className={styles.header}>
        <div>
          <h2>Theme Extensions</h2>
          <p>Customize the IDE appearance with CSS themes</p>
        </div>
        <button className={styles.primaryBtn} onClick={() => setShowInstall(!showInstall)}>
          {showInstall ? 'Cancel' : '+ Install Theme'}
        </button>
      </div>

      {showInstall && (
        <div className={styles.installPanel}>
          <h3>Install Custom Theme</h3>
          <div className={styles.form}>
            <div className={styles.formGroup}>
              <label>Theme ID (unique identifier, lowercase-dash)</label>
              <input
                type="text"
                value={themeId}
                onChange={(e) => setThemeId(e.target.value)}
                placeholder="my-custom-theme"
              />
            </div>
            <div className={styles.formGroup}>
              <label>Theme Name</label>
              <input
                type="text"
                value={themeName}
                onChange={(e) => setThemeName(e.target.value)}
                placeholder="My Custom Theme"
              />
            </div>
            <div className={styles.formGroup}>
              <label>Description</label>
              <input
                type="text"
                value={themeDesc}
                onChange={(e) => setThemeDesc(e.target.value)}
                placeholder="A beautiful custom theme"
              />
            </div>
            <div className={styles.formGroup}>
              <label>Author</label>
              <input
                type="text"
                value={themeAuthor}
                onChange={(e) => setThemeAuthor(e.target.value)}
                placeholder="Your Name"
              />
            </div>
            <div className={styles.formGroup}>
              <label>Theme CSS</label>
              <textarea
                value={themeCSS}
                onChange={(e) => setThemeCSS(e.target.value)}
                placeholder="Paste your theme CSS here..."
                rows={12}
              />
            </div>
            <div className={styles.buttonGroup}>
              <button className={styles.primaryBtn} onClick={installTheme}>
                Install Theme
              </button>
              <button className={styles.secondaryBtn} onClick={loadThemeTemplate}>
                Load Template
              </button>
            </div>
          </div>
        </div>
      )}

      <div className={styles.themeGrid}>
        {themes.map((theme) => (
          <div
            key={theme.id}
            className={`${styles.themeCard} ${currentTheme === theme.id ? styles.active : ''}`}
          >
            <div className={styles.themePreview} data-theme-preview={theme.id}>
              <div className={styles.previewBar}></div>
              <div className={styles.previewContent}>
                <div className={styles.previewSidebar}></div>
                <div className={styles.previewMain}></div>
              </div>
            </div>
            <div className={styles.themeInfo}>
              <h3>{theme.name}</h3>
              <p>{theme.description}</p>
              <div className={styles.themeMeta}>
                <span>{theme.author}</span>
                <span>v{theme.version}</span>
                {theme.builtIn && <span className={styles.badge}>Built-in</span>}
              </div>
            </div>
            <div className={styles.themeActions}>
              <button
                className={currentTheme === theme.id ? styles.activeBtn : styles.applyBtn}
                onClick={() => applyTheme(theme.id)}
                disabled={currentTheme === theme.id}
              >
                {currentTheme === theme.id ? 'Active' : 'Apply'}
              </button>
              {!theme.builtIn && (
                <>
                  <button className={styles.exportBtn} onClick={() => exportTheme(theme.id)}>
                    Export
                  </button>
                  <button className={styles.deleteBtn} onClick={() => uninstallTheme(theme.id)}>
                    Delete
                  </button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>

      <div className={styles.infoBox}>
        <h3>Creating Custom Themes</h3>
        <p>Themes use CSS variables to customize the IDE appearance. Required variables:</p>
        <ul>
          <li>
            <code>--color-bg-primary/secondary/tertiary/elevated/hover</code> - Background colors
          </li>
          <li>
            <code>--color-accent/accent-dim</code> - Accent colors
          </li>
          <li>
            <code>--color-text-primary/secondary/tertiary</code> - Text colors
          </li>
          <li>
            <code>--color-border/border-subtle</code> - Border colors
          </li>
          <li>
            <code>--color-success/warning/error</code> - Status colors
          </li>
        </ul>
        <p>Use the `:root[data-theme="your-theme-id"]` selector to scope your theme variables.</p>
      </div>
    </div>
  );
}
