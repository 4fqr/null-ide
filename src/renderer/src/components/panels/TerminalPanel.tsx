import React, { useEffect, useRef, useState } from 'react';
import { Terminal as XTerm } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import 'xterm/css/xterm.css';
import styles from './TerminalPanel.module.css';

interface TerminalPanelProps {
  isVisible: boolean;
  height: number;
  onHeightChange: (height: number) => void;
}

const TerminalPanel: React.FC<TerminalPanelProps> = ({ isVisible, height, onHeightChange }) => {
  const terminalRef = useRef<HTMLDivElement>(null);
  const [terminal, setTerminal] = useState<XTerm | null>(null);
  const [terminalId] = useState(`term-${Date.now()}`);
  const fitAddon = useRef<FitAddon>(new FitAddon());
  const [isResizing, setIsResizing] = useState(false);

  useEffect(() => {
    if (!terminalRef.current || terminal) return;

    const xterm = new XTerm({
      cursorBlink: true,
      cursorStyle: 'block',
      fontFamily: 'JetBrains Mono, Consolas, monospace',
      fontSize: 14,
      lineHeight: 1.2,
      theme: {
        background: '#0a0a0a',
        foreground: '#e0e0e0',
        cursor: '#00ffaa',
        cursorAccent: '#0a0a0a',
        selectionBackground: '#264f78',
        black: '#1a1a1a',
        red: '#ff5f87',
        green: '#00ffaa',
        yellow: '#ffff87',
        blue: '#5fafff',
        magenta: '#ff87ff',
        cyan: '#87ffff',
        white: '#e0e0e0',
        brightBlack: '#4a4a4a',
        brightRed: '#ff87af',
        brightGreen: '#87ffaf',
        brightYellow: '#ffffaf',
        brightBlue: '#87afff',
        brightMagenta: '#ffafff',
        brightCyan: '#afffff',
        brightWhite: '#ffffff',
      },
      scrollback: 10000,
      allowTransparency: false,
      convertEol: true,
    });

    xterm.loadAddon(fitAddon.current);
    xterm.open(terminalRef.current);
    
    // Initial fit with slight delay
    requestAnimationFrame(() => {
      try {
        fitAddon.current.fit();
      } catch (e) {
        console.error('Initial fit failed:', e);
      }
    });

    // Spawn terminal process (auto-detects shell based on OS)
    window.electronAPI.terminal.spawn(terminalId).then((res) => {
      if (res.success) {
        xterm.writeln('\x1b[1;32m✓\x1b[0m Terminal Ready');
        xterm.writeln('');
      } else {
        xterm.writeln(`\x1b[1;31m✗\x1b[0m Failed to start terminal: ${res.error}`);
      }
    });

    // Handle terminal input
    xterm.onData((data: string) => {
      window.electronAPI.terminal.write(terminalId, data);
    });

    // Handle terminal output
    window.electronAPI.terminal.onData((id, data) => {
      if (id === terminalId) {
        xterm.write(data);
      }
    });

    // Handle terminal exit
    window.electronAPI.terminal.onExit((id, code) => {
      if (id === terminalId) {
        xterm.writeln(`\n\x1b[33mProcess exited with code ${code}\x1b[0m`);
      }
    });

    setTerminal(xterm);

    // Add ResizeObserver to handle container size changes
    const resizeObserver = new ResizeObserver(() => {
      if (xterm && terminalRef.current) {
        try {
          fitAddon.current.fit();
        } catch (e) {
          // Ignore fit errors during rapid resizing
        }
      }
    });
    
    if (terminalRef.current) {
      resizeObserver.observe(terminalRef.current);
    }

    return () => {
      resizeObserver.disconnect();
      window.electronAPI.terminal.kill(terminalId);
      xterm.dispose();
    };
  }, [terminal, terminalId]);

  useEffect(() => {
    if (terminal && isVisible && terminalRef.current) {
      // Force multiple fit attempts to ensure proper sizing
      const fit = () => {
        try {
          fitAddon.current.fit();
        } catch (e) {
          console.error('Failed to fit terminal:', e);
        }
      };
      
      setTimeout(fit, 50);
      setTimeout(fit, 150);
      setTimeout(fit, 300);
    }
  }, [isVisible, terminal, height]);

  const handleResizeMouseDown = (e: React.MouseEvent) => {
    setIsResizing(true);
    const startY = e.clientY;
    const startHeight = height;

    const handleMouseMove = (e: MouseEvent) => {
      const delta = startY - e.clientY;
      const newHeight = Math.max(150, Math.min(600, startHeight + delta));
      onHeightChange(newHeight);
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
      if (terminal) {
        setTimeout(() => fitAddon.current.fit(), 50);
      }
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);
  };

  const handleClear = () => {
    terminal?.clear();
  };

  const handleNewTerminal = () => {
    // This would create a new terminal tab
    alert('Multiple terminals coming soon!');
  };

  if (!isVisible) return null;

  return (
    <div className={styles.terminalPanel} style={{ height: `${height}px` }}>
      <div 
        className={`${styles.resizeHandle} ${isResizing ? styles.resizing : ''}`}
        onMouseDown={handleResizeMouseDown}
      >
        <div className={styles.resizeLine} />
      </div>
      
      <div className={styles.toolbar}>
        <div className={styles.title}>
          <span className={styles.icon}>▶️</span>
          <span>Terminal</span>
        </div>
        <div className={styles.actions}>
          <button className={styles.btn} onClick={handleNewTerminal} title="New Terminal">
            ➕
          </button>
          <button className={styles.btn} onClick={handleClear} title="Clear Terminal">
            🗑️
          </button>
        </div>
      </div>

      <div ref={terminalRef} className={styles.terminalContainer} />
    </div>
  );
};

export default TerminalPanel;
