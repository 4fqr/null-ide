import React, { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import styles from './TerminalPanel.module.css';

interface TerminalInstance {
  id: string;
  name: string;
  terminal: XTerm;
  fitAddon: FitAddon;
}

interface TerminalPanelProps {
  isVisible: boolean;
  height: number;
  onHeightChange: (height: number) => void;
}

const TerminalPanel: React.FC<TerminalPanelProps> = ({ isVisible, height, onHeightChange }) => {
  const terminalContainerRef = useRef<HTMLDivElement>(null);
  const [terminals, setTerminals] = useState<TerminalInstance[]>([]);
  const [activeTerminalId, setActiveTerminalId] = useState<string | null>(null);
  const [isResizing, setIsResizing] = useState(false);

  const createTerminal = () => {
    const id = `term-${Date.now()}`;
    const name = `Terminal ${terminals.length + 1}`;
    
    const xterm = new XTerm({
      cursorBlink: true,
      cursorStyle: 'block',
      fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace",
      fontSize: 13,
      lineHeight: 1.4,
      theme: {
        background: '#050505',
        foreground: '#f0f0f0',
        cursor: '#00d9ff',
        black: '#0a0a0a',
        red: '#ff3366',
        green: '#00ff88',
        yellow: '#ffaa00',
        blue: '#0088ff',
        magenta: '#ff00ff',
        cyan: '#00d9ff',
        white: '#f0f0f0',
        brightBlack: '#404040',
        brightRed: '#ff5588',
        brightGreen: '#00ffaa',
        brightYellow: '#ffcc00',
        brightBlue: '#00aaff',
        brightMagenta: '#ff66ff',
        brightCyan: '#00ffff',
        brightWhite: '#ffffff',
      },
      scrollback: 10000,
      allowTransparency: true,
    });

    const fitAddon = new FitAddon();
    xterm.loadAddon(fitAddon);

    const newTerminal: TerminalInstance = {
      id,
      name,
      terminal: xterm,
      fitAddon,
    };

    setTerminals(prev => [...prev, newTerminal]);
    setActiveTerminalId(id);

    // Spawn terminal process after state update with proper retry logic
    const initializeTerminal = () => {
      const container = document.getElementById(`terminal-${id}`);
      if (container && container.offsetParent !== null) { // Check if visible in DOM
        xterm.open(container);
        
        // Fit with retry
        try {
          fitAddon.fit();
        } catch (e) {
          setTimeout(() => {
            try { fitAddon.fit(); } catch { /* ignore */ }
          }, 200);
        }

        // Spawn PowerShell process
        window.electronAPI.terminal.spawn(id, 'powershell.exe').then((res) => {
          if (res.success) {
            xterm.writeln('\x1b[1;32m✓\x1b[0m PowerShell Ready');
            xterm.writeln('');
          } else {
            xterm.writeln(`\x1b[1;31m✗\x1b[0m Failed: ${res.error}`);
          }
        }).catch((err) => {
          xterm.writeln(`\x1b[1;31m✗\x1b[0m Error: ${err.message}`);
        });

        // Setup data handlers
        xterm.onData((data) => {
          window.electronAPI.terminal.write(id, data);
        });

        window.electronAPI.terminal.onData((termId, data) => {
          if (termId === id) {
            xterm.write(data);
          }
        });

        window.electronAPI.terminal.onExit((termId, code) => {
          if (termId === id) {
            xterm.writeln(`\n\x1b[33mProcess exited with code ${code}\x1b[0m`);
          }
        });
      } else {
        // Container not ready, retry with longer delay
        console.log(`Terminal ${id} container not ready, retrying...`);
        setTimeout(initializeTerminal, 200);
      }
    };
    
    // Start initialization with longer initial delay
    setTimeout(initializeTerminal, 500);

    return newTerminal;
  };

  const closeTerminal = (id: string) => {
    const terminal = terminals.find(t => t.id === id);
    if (terminal) {
      window.electronAPI.terminal.kill(id);
      terminal.terminal.dispose();
      setTerminals(prev => prev.filter(t => t.id !== id));
      
      if (activeTerminalId === id) {
        const remaining = terminals.filter(t => t.id !== id);
        setActiveTerminalId(remaining.length > 0 ? remaining[0].id : null);
      }
    }
  };

  useEffect(() => {
    // Always create initial terminal with proper delay
    if (terminals.length === 0) {
      // Delay to ensure DOM is ready
      const timer = setTimeout(() => {
        createTerminal();
      }, 100);
      return () => clearTimeout(timer);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    // Force create terminal when becoming visible if none exist
    if (isVisible && terminals.length === 0) {
      createTerminal();
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [isVisible]);

  useEffect(() => {
    // Fit terminals when visible or when height/active terminal changes
    if (terminals.length > 0) {
      const fitTimer = setTimeout(() => {
        terminals.forEach(t => {
          if (t.id === activeTerminalId) {
            try {
              t.fitAddon.fit();
            } catch (e) {
              // Terminal may not be fully initialized yet
              console.debug('Terminal fit skipped:', e);
            }
          }
        });
      }, isVisible ? 150 : 300); // Longer delay if not visible
      
      return () => clearTimeout(fitTimer);
    }
  }, [isVisible, height, activeTerminalId, terminals]);

  useEffect(() => {
    return () => {
      terminals.forEach(t => {
        window.electronAPI.terminal.kill(t.id);
        t.terminal.dispose();
      });
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleMouseDown = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
  };

  useEffect(() => {
    if (!isResizing) return;

    const handleMouseMove = (e: MouseEvent) => {
      const newHeight = window.innerHeight - e.clientY;
      onHeightChange(Math.max(100, Math.min(600, newHeight)));
    };

    const handleMouseUp = () => {
      setIsResizing(false);
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isResizing, onHeightChange]);

  if (!isVisible) return null;

  return (
    <div className={styles.terminalPanel} style={{ height: `${height}px` }}>
      <div className={styles.resizeHandle} onMouseDown={handleMouseDown} />
      
      <div className={styles.terminalHeader}>
        <div className={styles.terminalTabs}>
          {terminals.map(term => (
            <div
              key={term.id}
              className={`${styles.terminalTab} ${activeTerminalId === term.id ? styles.active : ''}`}
              onClick={() => setActiveTerminalId(term.id)}
            >
              <span>{term.name}</span>
              <button
                className={styles.closeButton}
                onClick={(e) => {
                  e.stopPropagation();
                  closeTerminal(term.id);
                }}
              >
                ×
              </button>
            </div>
          ))}
          <button className={styles.newTerminalButton} onClick={createTerminal}>
            + New Terminal
          </button>
        </div>
      </div>

      <div className={styles.terminalContent} ref={terminalContainerRef}>
        {terminals.map(term => (
          <div
            key={term.id}
            id={`terminal-${term.id}`}
            className={styles.terminalInstance}
            style={{ display: activeTerminalId === term.id ? 'block' : 'none' }}
          />
        ))}
      </div>
    </div>
  );
};

export default TerminalPanel;
