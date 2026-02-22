export interface Theme {
  id: string;
  name: string;
  description: string;
  author: string;
  version: string;
  builtIn: boolean;
}

export const defaultThemes: Theme[] = [
  {
    id: 'null-dark',
    name: 'Null Dark',
    description: 'Ultra-minimal dark theme with cyan accents',
    author: 'Null IDE',
    version: '1.0.0',
    builtIn: true
  },
  {
    id: 'cyber-purple',
    name: 'Cyber Purple',
    description: 'Cyberpunk-inspired purple theme',
    author: 'Null IDE',
    version: '1.0.0',
    builtIn: true
  },
  {
    id: 'matrix-green',
    name: 'Matrix Green',
    description: 'Classic Matrix terminal green',
    author: 'Null IDE',
    version: '1.0.0',
    builtIn: true
  },
  {
    id: 'nord',
    name: 'Nord',
    description: 'Arctic, north-bluish color palette',
    author: 'Null IDE',
    version: '1.0.0',
    builtIn: true
  },
  {
    id: 'dracula',
    name: 'Dracula',
    description: 'Dark theme with purple accents',
    author: 'Null IDE',
    version: '1.0.0',
    builtIn: true
  },
  {
    id: 'tokyo-night',
    name: 'Tokyo Night',
    description: 'Clean, dark blue theme',
    author: 'Null IDE',
    version: '1.0.0',
    builtIn: true
  },
  {
    id: 'gruvbox-dark',
    name: 'Gruvbox Dark',
    description: 'Retro groove with warm colors',
    author: 'Null IDE',
    version: '1.0.0',
    builtIn: true
  },
  {
    id: 'one-dark-pro',
    name: 'One Dark Pro',
    description: 'Atom One Dark inspired theme',
    author: 'Null IDE',
    version: '1.0.0',
    builtIn: true
  }
];

export class ThemeManager {
  private static STORAGE_KEY = 'null-ide-active-theme';
  private static CUSTOM_THEMES_KEY = 'null-ide-custom-themes';

  static getCurrentTheme(): string {
    return localStorage.getItem(this.STORAGE_KEY) || 'null-dark';
  }

  static setTheme(themeId: string): void {
    localStorage.setItem(this.STORAGE_KEY, themeId);
    document.documentElement.setAttribute('data-theme', themeId);
  }

  static getCustomThemes(): Theme[] {
    const stored = localStorage.getItem(this.CUSTOM_THEMES_KEY);
    return stored ? JSON.parse(stored) : [];
  }

  static getAllThemes(): Theme[] {
    return [...defaultThemes, ...this.getCustomThemes()];
  }

  static installTheme(themeCSS: string, metadata: Omit<Theme, 'builtIn'>): boolean {
    try {
      
      if (!themeCSS.includes(':root[data-theme="' + metadata.id + '"]')) {
        throw new Error('Theme CSS must use :root[data-theme="..."] selector');
      }

      
      const existingThemes = this.getAllThemes();
      if (existingThemes.some(t => t.id === metadata.id)) {
        throw new Error('Theme with this ID already exists');
      }

      
      const styleEl = document.createElement('style');
      styleEl.id = `theme-${metadata.id}`;
      styleEl.textContent = themeCSS;
      document.head.appendChild(styleEl);

      
      const customThemes = this.getCustomThemes();
      customThemes.push({ ...metadata, builtIn: false });
      localStorage.setItem(this.CUSTOM_THEMES_KEY, JSON.stringify(customThemes));

      return true;
    } catch (error) {
      console.error('Failed to install theme:', error);
      return false;
    }
  }

  static uninstallTheme(themeId: string): boolean {
    const customThemes = this.getCustomThemes();
    const theme = customThemes.find(t => t.id === themeId);
    
    if (!theme) {
      return false;
    }

    
    const styleEl = document.getElementById(`theme-${themeId}`);
    if (styleEl) {
      styleEl.remove();
    }

    
    const updatedThemes = customThemes.filter(t => t.id !== themeId);
    localStorage.setItem(this.CUSTOM_THEMES_KEY, JSON.stringify(updatedThemes));

    
    if (this.getCurrentTheme() === themeId) {
      this.setTheme('null-dark');
    }

    return true;
  }

  static exportTheme(themeId: string): string | null {
    const styleEl = document.getElementById(`theme-${themeId}`);
    if (!styleEl) return null;

    const customThemes = this.getCustomThemes();
    const theme = customThemes.find(t => t.id === themeId);
    
    if (!theme) return null;

    return JSON.stringify({
      metadata: theme,
      css: styleEl.textContent
    }, null, 2);
  }

  static loadCustomThemesFromStorage(): void {
    const customThemes = this.getCustomThemes();
    customThemes.forEach(theme => {
      
      
      const css = localStorage.getItem(`theme-css-${theme.id}`);
      if (css) {
        const styleEl = document.createElement('style');
        styleEl.id = `theme-${theme.id}`;
        styleEl.textContent = css;
        document.head.appendChild(styleEl);
      }
    });
  }
}

export function initializeTheme(): void {
  const currentTheme = ThemeManager.getCurrentTheme();
  ThemeManager.setTheme(currentTheme);
  ThemeManager.loadCustomThemesFromStorage();
}
