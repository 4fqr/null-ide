import { app, BrowserWindow, ipcMain, BrowserView } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as net from 'net';
import * as dns from 'dns';
import { promisify } from 'util';
import { spawn } from 'child_process';

const dnsResolve = promisify(dns.resolve);
const dnsReverse = promisify(dns.reverse);

let mainWindow: BrowserWindow | null = null;
let deephatBrowserView: BrowserView | null = null;
let fileToOpen: string | null = null;

const isDev = process.env.NODE_ENV === 'development';

// Handle file/folder opening from context menu
if (process.argv.length > 1) {
  const argPath = process.argv[process.argv.length - 1];
  if (argPath && !argPath.includes('--') && fs.existsSync(argPath)) {
    fileToOpen = argPath;
  }
}

/**
 * Create the main application window
 */
function createWindow() {
  console.log('Creating main window...');
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 700,
    title: 'Null IDE – NullSec',
    icon: path.join(__dirname, 'null_ide.png'),
    backgroundColor: '#0a0a0a',
    webPreferences: {
      preload: path.join(__dirname, '../preload/preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
    },
    autoHideMenuBar: true,
  });

  console.log('Window created, loading URL...');
  // Load the app
  if (isDev) {
    console.log('Dev mode: loading http://localhost:5173');
    mainWindow.loadURL('http://localhost:5173').catch((err) => {
      console.error('Failed to load URL:', err);
    });
    // DevTools can be opened with F12 or Ctrl+Shift+I
  } else {
    console.log('Production mode: loading from file');
    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html')).catch((err) => {
      console.error('Failed to load file:', err);
    });
  }

  mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription) => {
    console.error('Page failed to load:', errorCode, errorDescription);
  });

  mainWindow.webContents.on('crashed', () => {
    console.error('Renderer process crashed!');
  });

  mainWindow.on('unresponsive', () => {
    console.error('Window became unresponsive');
  });

  mainWindow.on('closed', () => {
    console.log('Main window closed');
    mainWindow = null;
    deephatBrowserView = null;
  });
}

/**
 * Create and attach the DeepHat browser view for the right sidebar
 */
function createDeepHatView() {
  if (!mainWindow) return;

  deephatBrowserView = new BrowserView({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  mainWindow.addBrowserView(deephatBrowserView);
  deephatBrowserView.webContents.loadURL('https://app.deephat.ai/');
}

/**
 * Position the DeepHat browser view (called when sidebar is shown/resized)
 */
ipcMain.on('position-deephat-view', (event, bounds) => {
  if (deephatBrowserView) {
    deephatBrowserView.setBounds(bounds);
  }
});

/**
 * Show/hide the DeepHat browser view
 */
ipcMain.on('toggle-deephat-view', (event, show) => {
  if (!mainWindow) return;

  if (show && !deephatBrowserView) {
    createDeepHatView();
  } else if (!show && deephatBrowserView) {
    mainWindow.removeBrowserView(deephatBrowserView);
    deephatBrowserView = null;
  }
});

/**
 * Reload DeepHat view
 */
ipcMain.on('reload-deephat', () => {
  if (deephatBrowserView) {
    deephatBrowserView.webContents.reload();
  }
});

/**
 * File system operations
 */
ipcMain.handle('fs:readFile', async (event, filePath: string) => {
  try {
    const content = await fs.promises.readFile(filePath, 'utf-8');
    return { success: true, content };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('fs:writeFile', async (event, filePath: string, content: string) => {
  try {
    await fs.promises.writeFile(filePath, content, 'utf-8');
    return { success: true };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('fs:readDir', async (event, dirPath: string) => {
  try {
    const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
    // Limit to 500 items to prevent crashes
    const limitedEntries = entries.slice(0, 500);
    const items = limitedEntries.map((entry) => ({
      name: entry.name,
      isDirectory: entry.isDirectory(),
      path: path.join(dirPath, entry.name),
    }));
    return { success: true, items, truncated: entries.length > 500 };
  } catch (error: any) {
    console.error('Error reading directory:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('fs:exists', async (event, filePath: string) => {
  try {
    await fs.promises.access(filePath);
    return { success: true, exists: true };
  } catch {
    return { success: true, exists: false };
  }
});

ipcMain.handle('fs:stat', async (event, filePath: string) => {
  try {
    const stats = await fs.promises.stat(filePath);
    return {
      success: true,
      stats: {
        isFile: stats.isFile(),
        isDirectory: stats.isDirectory(),
        size: stats.size,
        modified: stats.mtime,
      },
    };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

/**
 * App info
 */
ipcMain.handle('app:getVersion', () => {
  return app.getVersion();
});

ipcMain.handle('app:getUserDataPath', () => {
  return app.getPath('userData');
});

/**
 * Config storage
 */
ipcMain.handle('config:read', async () => {
  try {
    const configPath = path.join(app.getPath('userData'), 'config.json');
    if (fs.existsSync(configPath)) {
      const content = await fs.promises.readFile(configPath, 'utf-8');
      return { success: true, config: JSON.parse(content) };
    }
    return { success: true, config: {} };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('config:write', async (event, config: any) => {
  try {
    const configPath = path.join(app.getPath('userData'), 'config.json');
    await fs.promises.writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8');
    return { success: true };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

/**
 * Hashing utilities
 */
ipcMain.handle('crypto:hash', (event, algorithm: string, data: string) => {
  try {
    const hash = crypto.createHash(algorithm).update(data).digest('hex');
    return { success: true, hash };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

/**
 * Network utilities
 */
ipcMain.handle('net:scanPort', async (event, host: string, port: number, timeout = 1000) => {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let isOpen = false;

    socket.setTimeout(timeout);

    socket.on('connect', () => {
      isOpen = true;
      socket.destroy();
    });

    socket.on('timeout', () => {
      socket.destroy();
    });

    socket.on('error', () => {
      socket.destroy();
    });

    socket.on('close', () => {
      resolve({ success: true, isOpen, host, port });
    });

    socket.connect(port, host);
  });
});

ipcMain.handle('net:dnsLookup', async (event, hostname: string) => {
  try {
    const addresses = await dnsResolve(hostname);
    return { success: true, addresses };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

ipcMain.handle('net:reverseDns', async (event, ip: string) => {
  try {
    const hostnames = await dnsReverse(ip);
    return { success: true, hostnames };
  } catch (error: any) {
    return { success: false, error: error.message };
  }
});

/**
 * Dialog operations
 */
ipcMain.handle('dialog:openFile', async () => {
  const { dialog } = require('electron');
  const result = await dialog.showOpenDialog(mainWindow!, {
    properties: ['openFile'],
  });
  return result;
});

ipcMain.handle('dialog:saveFile', async () => {
  const { dialog } = require('electron');
  const result = await dialog.showSaveDialog(mainWindow!, {});
  return result;
});

ipcMain.handle('dialog:openDirectory', async () => {
  const { dialog } = require('electron');
  const result = await dialog.showOpenDialog(mainWindow!, {
    properties: ['openDirectory'],
  });
  return result;
});

/**
 * Terminal operations
 */
const terminals = new Map<string, any>();

ipcMain.handle('terminal:spawn', (event, terminalId: string, shell: string = 'powershell.exe', cwd?: string) => {
  try {
    console.log(`Spawning terminal ${terminalId} with shell ${shell}`);
    const ptyProcess = spawn(shell, [], {
      cwd: cwd || process.cwd(),
      env: process.env,
      shell: true,
      windowsHide: true,
    });

    if (!ptyProcess || !ptyProcess.pid) {
      throw new Error('Failed to spawn terminal process');
    }

    terminals.set(terminalId, ptyProcess);

    ptyProcess.stdout?.on('data', (data) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('terminal:data', terminalId, data.toString());
      }
    });

    ptyProcess.stderr?.on('data', (data) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('terminal:data', terminalId, data.toString());
      }
    });

    ptyProcess.on('exit', (code) => {
      console.log(`Terminal ${terminalId} exited with code ${code}`);
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('terminal:exit', terminalId, code);
      }
      terminals.delete(terminalId);
    });

    ptyProcess.on('error', (err) => {
      console.error(`Terminal ${terminalId} error:`, err);
      terminals.delete(terminalId);
    });

    console.log(`Terminal ${terminalId} spawned successfully with PID ${ptyProcess.pid}`);
    return { success: true, pid: ptyProcess.pid };
  } catch (error: any) {
    console.error('Error spawning terminal:', error);
    return { success: false, error: error.message };
  }
});

ipcMain.handle('terminal:write', (event, terminalId: string, data: string) => {
  const terminal = terminals.get(terminalId);
  if (terminal && terminal.stdin) {
    terminal.stdin.write(data);
    return { success: true };
  }
  return { success: false, error: 'Terminal not found' };
});

ipcMain.handle('terminal:resize', (event, terminalId: string, cols: number, rows: number) => {
  // For basic terminals, we can't resize, but we return success
  return { success: true };
});

ipcMain.handle('terminal:kill', (event, terminalId: string) => {
  const terminal = terminals.get(terminalId);
  if (terminal) {
    terminal.kill();
    terminals.delete(terminalId);
    return { success: true };
  }
  return { success: false, error: 'Terminal not found' };
});

/**
 * Handle getting initial file/folder to open
 */
ipcMain.handle('app:getInitialPath', () => {
  return fileToOpen;
});

/**
 * App lifecycle
 */
app.whenReady().then(() => {
  console.log('App ready, creating window...');
  createWindow();
  console.log('Window created successfully');
  
  // Send initial file path to renderer after window loads
  if (fileToOpen && mainWindow) {
    mainWindow.webContents.on('did-finish-load', () => {
      mainWindow?.webContents.send('open-initial-path', fileToOpen);
    });
  }

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Handle opening files from Windows Explorer when app is already running
app.on('second-instance', (_event, commandLine) => {
  if (mainWindow) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.focus();
    
    const filePath = commandLine[commandLine.length - 1];
    if (filePath && !filePath.includes('--') && fs.existsSync(filePath)) {
      mainWindow.webContents.send('open-initial-path', filePath);
    }
  }
});

// Prevent multiple instances
const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
}

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});
