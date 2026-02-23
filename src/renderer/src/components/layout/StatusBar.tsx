import React, { useState, useEffect } from 'react';
import { useStore } from '../../store/store';
import styles from './StatusBar.module.css';

declare global {
  interface Window {
    electronAPI: {
      live: {
        start: (content: string) => Promise<{ success: boolean; error?: string }>;
        stop: () => Promise<{ success: boolean }>;
        onStatus: (callback: (isRunning: boolean, message: string) => void) => void;
      };
      fs: {
        readFile: (path: string) => Promise<{ success: boolean; content?: string; error?: string }>;
        writeFile: (path: string, content: string) => Promise<{ success: boolean; error?: string }>;
        readDir: (dirPath: string) => Promise<{
          success: boolean;
          items?: Array<{ name: string; isDirectory: boolean; path: string }>;
          error?: string;
        }>;
        exists: (filePath: string) => Promise<{ success: boolean; exists: boolean }>;
        stat: (filePath: string) => Promise<{
          success: boolean;
          stats?: { isFile: boolean; isDirectory: boolean; size: number; modified: Date };
          error?: string;
        }>;
        createFile: (filePath: string) => Promise<{ success: boolean; error?: string }>;
        createFolder: (folderPath: string) => Promise<{ success: boolean; error?: string }>;
        deleteFile: (filePath: string) => Promise<{ success: boolean; error?: string }>;
        deleteFolder: (folderPath: string) => Promise<{ success: boolean; error?: string }>;
        rename: (oldPath: string, newPath: string) => Promise<{ success: boolean; error?: string }>;
      };
      dialog: {
        openFile: () => Promise<{ canceled: boolean; filePaths: string[]; error?: string }>;
        saveFile: () => Promise<{ canceled: boolean; filePath?: string; error?: string }>;
        openDirectory: () => Promise<{ canceled: boolean; filePaths: string[]; error?: string }>;
        selectFolder: () => Promise<{ canceled: boolean; filePaths: string[]; error?: string }>;
      };
      app: {
        getVersion: () => Promise<string>;
        getUserDataPath: () => Promise<string>;
        getInitialPath: () => Promise<string | null>;
        onOpenPath: (callback: (path: string) => void) => void;
      };
      config: {
        read: () => Promise<{ success: boolean; config?: Record<string, unknown>; error?: string }>;
        write: (config: Record<string, unknown>) => Promise<{ success: boolean; error?: string }>;
      };
      crypto: {
        hash: (
          algorithm: string,
          data: string
        ) => Promise<{ success: boolean; hash?: string; error?: string }>;
      };
      net: {
        scanPort: (
          host: string,
          port: number,
          timeout?: number
        ) => Promise<{
          success: boolean;
          isOpen?: boolean;
          host?: string;
          port?: number;
          error?: string;
        }>;
        dnsLookup: (
          hostname: string
        ) => Promise<{ success: boolean; addresses?: string[]; error?: string }>;
        reverseDns: (
          ip: string
        ) => Promise<{ success: boolean; hostnames?: string[]; error?: string }>;
        httpFetch: (
          url: string,
          options?: Record<string, unknown>
        ) => Promise<{
          success: boolean;
          status?: number;
          statusText?: string;
          headers?: Record<string, string>;
          data?: string;
          error?: string;
        }>;
      };
      terminal: {
        spawn: (
          terminalId: string,
          shell?: string,
          cwd?: string
        ) => Promise<{ success: boolean; pid?: number; error?: string }>;
        write: (terminalId: string, data: string) => Promise<{ success: boolean; error?: string }>;
        resize: (terminalId: string, cols: number, rows: number) => Promise<{ success: boolean }>;
        kill: (terminalId: string) => Promise<{ success: boolean; error?: string }>;
        onData: (callback: (terminalId: string, data: string) => void) => void;
        onExit: (callback: (terminalId: string, code: number) => void) => void;
      };
      discord: {
        updateActivity: (fileName: string | null) => void;
      };
    };
  }
}

const StatusBar: React.FC = () => {
  const { tabs, activeTabId, mode, rightSidebarVisible, toggleRightSidebar } = useStore();
  const activeTab = tabs.find((tab) => tab.id === activeTabId);
  const [isLive, setIsLive] = useState(false);

  useEffect(() => {
    if (window.electronAPI?.live?.onStatus) {
      window.electronAPI.live.onStatus((running) => {
        setIsLive(running);
      });
    }
  }, []);

  const handleGoLive = async () => {
    if (!window.electronAPI?.live) {
      console.error('Live API not available');
      return;
    }

    if (isLive) {
      await window.electronAPI.live.stop();
      setIsLive(false);
      return;
    }

    let content =
      '<!DOCTYPE html><html><head><title>Null IDE Live</title><style>body{background:#0a0a0a;color:#00ffaa;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;flex-direction:column;}h1{margin:0 0 10px 0;}</style></head><body><h1>Null IDE Live Server</h1><p>No file open - Open a file to preview it live</p></body></html>';

    if (activeTab?.content) {
      const tabContent = activeTab.content;
      if (
        activeTab.language === 'html' ||
        activeTab.path?.endsWith('.html') ||
        activeTab.path?.endsWith('.htm')
      ) {
        content = tabContent;
      } else if (activeTab.language === 'markdown' || activeTab.path?.endsWith('.md')) {
        const mdHtml = `<!DOCTYPE html><html><head><title>${activeTab.name}</title><style>body{background:#0a0a0a;color:#e0e0e0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;max-width:900px;margin:0 auto;padding:40px 20px;line-height:1.6;}pre,code{background:#1a1a1a;padding:2px 6px;border-radius:4px;}pre{padding:16px;overflow-x:auto;}h1,h2,h3{color:#00ffaa;border-bottom:1px solid #333;padding-bottom:8px;}a{color:#00d4ff;}blockquote{border-left:3px solid #00ffaa;margin:0;padding-left:16px;color:#888;}</style></head><body>${tabContent}</body></html>`;
        content = mdHtml;
      } else {
        const ext = activeTab.path?.split('.').pop() || 'txt';
        const langMap: Record<string, string> = {
          js: 'javascript',
          ts: 'typescript',
          jsx: 'javascript',
          tsx: 'typescript',
          py: 'python',
          rb: 'ruby',
          go: 'go',
          rs: 'rust',
          java: 'java',
          cpp: 'cpp',
          c: 'c',
          cs: 'csharp',
          php: 'php',
          swift: 'swift',
          kt: 'kotlin',
          scala: 'scala',
          r: 'r',
          sql: 'sql',
          sh: 'bash',
          json: 'json',
          yaml: 'yaml',
          yml: 'yaml',
          xml: 'xml',
          css: 'css',
          scss: 'scss',
          sass: 'sass',
          less: 'less',
        };
        const lang = langMap[ext] || 'plaintext';
        content = `<!DOCTYPE html><html><head><title>${activeTab.name}</title><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/styles/atom-one-dark.min.css"><style>body{background:#0a0a0a;color:#e0e0e0;font-family:monospace;margin:0;padding:0;}.container{max-width:100%;}pre{margin:0;padding:20px;background:#1a1a1a;overflow-x:auto;}code{font-family:'JetBrains Mono','Fira Code',Consolas,monospace;font-size:14px;line-height:1.6;}.header{background:#0f0f0f;padding:12px 20px;border-bottom:1px solid #333;display:flex;align-items:center;gap:10px;}.filename{color:#00ffaa;font-weight:600;}.lang{color:#666;font-size:12px;padding:2px 8px;background:#1a1a1a;border-radius:4px;}</style></head><body><div class="header"><span class="filename">${activeTab.name}</span><span class="lang">${lang.toUpperCase()}</span></div><div class="container"><pre><code class="language-${lang}">${tabContent.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</code></pre></div><script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.9.0/highlight.min.js"></script><script>hljs.highlightAll();</script></body></html>`;
      }
    }

    const result = await window.electronAPI.live.start(content);
    if (result.success) {
      setIsLive(true);
    } else {
      console.error('Failed to start live server:', result.error);
    }
  };

  const openInBrowser = () => {
    if (isLive) {
      window.open('http://localhost:8080', '_blank');
    }
  };

  return (
    <div className={styles.statusBar}>
      <div className={styles.left}>
        {activeTab && (
          <>
            <div className={styles.item}>
              <span className={styles.language}>{activeTab.language.toUpperCase()}</span>
            </div>
            {activeTab.modified && (
              <>
                <div className={styles.separator} />
                <div className={styles.item}>
                  <span className={styles.modified}>Modified</span>
                </div>
              </>
            )}
          </>
        )}
        <div className={styles.separator} />
        <button
          className={`${styles.goLiveButton} ${isLive ? styles.active : ''}`}
          onClick={handleGoLive}
          title={isLive ? 'Stop Live Preview' : 'Start Live Preview on localhost:8080'}
        >
          {isLive && <span className={styles.liveIndicator} />}
          <span>{isLive ? 'Stop Server' : 'Go Live'}</span>
        </button>
        {isLive && <span className={styles.portMessage}>Port opened: 8080</span>}
        {isLive && (
          <button className={styles.browserBtn} onClick={openInBrowser} title="Open in Browser">
            Open Browser
          </button>
        )}
      </div>

      <div className={styles.center}>
        <div className={styles.item}>
          <span className={styles.mode}>{mode === 'code' ? 'Code Mode' : 'Utility Mode'}</span>
        </div>
      </div>

      <div className={styles.right}>
        <button
          className={`${styles.aiButton} ${rightSidebarVisible ? styles.active : ''}`}
          onClick={toggleRightSidebar}
          title="Toggle DeepChat AI"
        >
          <span className={styles.aiIcon}>AI</span>
          <span>{rightSidebarVisible ? 'Hide AI' : 'DeepChat AI'}</span>
        </button>
        <div className={styles.separator} />
        <div className={styles.item}>
          <span className={styles.version}>v3.5.0</span>
        </div>
      </div>
    </div>
  );
};

export default StatusBar;
