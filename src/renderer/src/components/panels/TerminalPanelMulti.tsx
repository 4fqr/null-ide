import React, { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import '@xterm/xterm/css/xterm.css';
import styles from './TerminalPanel.module.css';

interface TerminalInstance {
  id: string;
  name: string;
  terminal: XTerm;
  fitAddon: FitAddon;
  shell: string;
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
  const [defaultShell, setDefaultShell] = useState<string>('');
  const [showShellSelector, setShowShellSelector] = useState(false);

  useEffect(() => {
    const detectShell = () => {
      if (navigator.platform.includes('Win')) {
        setDefaultShell('powershell.exe');
      } else if (navigator.platform.includes('Mac')) {
        setDefaultShell('/bin/zsh');
      } else {
        setDefaultShell('/bin/bash');
      }
    };
    detectShell();
  }, []);

  const getShellOptions = () => {
    if (navigator.platform.includes('Win')) {
      return [
        { value: 'powershell.exe', label: 'PowerShell' },
        { value: 'cmd.exe', label: 'Command Prompt' },
      ];
    } else {
      return [
        { value: '/bin/bash', label: 'Bash' },
        { value: '/bin/zsh', label: 'Zsh' },
        { value: '/bin/sh', label: 'SH' },
      ];
    }
  };

  const createTerminal = (shellOverride?: string) => {
    const id = `term-${Date.now()}`;
    const shell = shellOverride || defaultShell;
    const shellName = shell.includes('bash')
      ? 'Bash'
      : shell.includes('zsh')
        ? 'Zsh'
        : shell.includes('powershell')
          ? 'PowerShell'
          : shell.includes('cmd')
            ? 'CMD'
            : 'Terminal';
    const name = `${shellName} ${terminals.length + 1}`;

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
      fastScrollModifier: 'alt',
      fastScrollSensitivity: 5,
      scrollSensitivity: 3,
    });

    const fitAddon = new FitAddon();
    xterm.loadAddon(fitAddon);

    const newTerminal: TerminalInstance = {
      id,
      name,
      terminal: xterm,
      fitAddon,
      shell,
    };

    setTerminals((prev) => [...prev, newTerminal]);
    setActiveTerminalId(id);
    setShowShellSelector(false);

    const initializeTerminal = () => {
      const container = document.getElementById(`terminal-${id}`);
      if (container && container.offsetParent !== null) {
        xterm.open(container);

        try {
          fitAddon.fit();
        } catch (e) {
          setTimeout(() => {
            try {
              fitAddon.fit();
            } catch {
              void 0;
            }
          }, 200);
        }

        if (window.electronAPI?.terminal) {
          window.electronAPI.terminal
            .spawn(id, shell)
            .then((res) => {
              if (res.success) {
                xterm.writeln(`\x1b[1;32m✓\x1b[0m ${shellName} Ready`);
                xterm.writeln('');
              } else {
                xterm.writeln(`\x1b[1;31m✗\x1b[0m Failed: ${res.error}`);
              }
            })
            .catch((err) => {
              xterm.writeln(`\x1b[1;31m✗\x1b[0m Error: ${err.message}`);
            });

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
           xterm.writeln(`\x1b[1;31m✗\x1b[0m Electron API not available`);
        }
      } else {
        setTimeout(initializeTerminal, 200);
      }
    };

    setTimeout(initializeTerminal, 500);

    return newTerminal;
  };

  const closeTerminal = (id: string) => {
    const terminal = terminals.find((t) => t.id === id);
    if (terminal) {
      if (window.electronAPI?.terminal) {
        window.electronAPI.terminal.kill(id);
      }
      terminal.terminal.dispose();
      setTerminals((prev) => prev.filter((t) => t.id !== id));

      if (activeTerminalId === id) {
        const remaining = terminals.filter((t) => t.id !== id);
        setActiveTerminalId(remaining.length > 0 ? remaining[0].id : null);
      }
    }
  };

  useEffect(() => {
    if (terminals.length === 0) {
      const timer = setTimeout(() => {
        createTerminal();
      }, 100);
      return () => clearTimeout(timer);
    }
  }, []);

  useEffect(() => {
    if (isVisible && terminals.length === 0) {
      createTerminal();
    }
  }, [isVisible]);

  useEffect(() => {
    if (terminals.length > 0) {
      const fitTimer = setTimeout(
        () => {
          terminals.forEach((t) => {
            if (t.id === activeTerminalId) {
              try {
                t.fitAddon.fit();
              } catch {
                void 0;
              }
            }
          });
        },
        isVisible ? 150 : 300
      );

      return () => clearTimeout(fitTimer);
    }
  }, [isVisible, height, activeTerminalId, terminals]);

  useEffect(() => {
    return () => {
      terminals.forEach((t) => {
        if (window.electronAPI?.terminal) {
          window.electronAPI.terminal.kill(t.id);
        }
        t.terminal.dispose();
      });
    };
  }, []);

  const handleMouseDown = (e: React.MouseEvent) => {
    e.preventDefault();
    setIsResizing(true);
  };

  useEffect(() => {
    if (!isResizing) return;

    const handleMouseMove = (e: MouseEvent) => {
      const newHeight = window.innerHeight - e.clientY;
      onHeightChange(Math.max(50, Math.min(800, newHeight)));
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

  const handleNewTerminal = () => {
    if (getShellOptions().length > 1) {
      setShowShellSelector(!showShellSelector);
    } else {
      createTerminal();
    }
  };

  const handleShellSelect = (shell: string) => {
    createTerminal(shell);
  };

  return (
    <div
      className={styles.terminalPanel}
      style={{
        height: isVisible ? `${height}px` : '0px',
        display: isVisible ? 'flex' : 'none',
      }}
    >
      <div className={styles.resizeHandle} onMouseDown={handleMouseDown} />

      <div className={styles.terminalHeader}>
        <div className={styles.terminalTabs}>
          {terminals.map((term) => (
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
          <button className={styles.newTerminalButton} onClick={handleNewTerminal}>
            + New Terminal
          </button>
          {showShellSelector && (
            <div className={styles.shellSelector}>
              {getShellOptions().map((option) => (
                <button
                  key={option.value}
                  className={styles.shellOption}
                  onClick={() => handleShellSelect(option.value)}
                >
                  {option.label}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div className={styles.terminalContent} ref={terminalContainerRef}>
        {terminals.map((term) => (
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
