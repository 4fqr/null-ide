import { app, BrowserWindow, ipcMain, BrowserView } from 'electron';
import * as path from 'path';
import * as fs from 'fs';
import * as crypto from 'crypto';
import * as net from 'net';
import * as dns from 'dns';
import { promisify } from 'util';
import * as pty from 'node-pty';
import {
  initDiscordRPC,
  updateActivity,
  disconnectDiscordRPC,
  isDiscordConnected,
} from './discordRPC';
import type { AppConfig, HttpFetchOptions, HttpResponse } from '../types/api';

const dnsResolve = promisify(dns.resolve);
const dnsReverse = promisify(dns.reverse);

let mainWindow: BrowserWindow | null = null;
let deephatBrowserView: BrowserView | null = null;
let fileToOpen: string | null = null;

const isDev = process.env.NODE_ENV === 'development';

function getUserFriendlyError(error: NodeJS.ErrnoException): string {
  switch (error.code) {
    case 'ENOENT':
      return `File or folder not found: ${error.path}`;
    case 'EACCES':
    case 'EPERM':
      return `Permission denied: ${error.path}`;
    case 'EEXIST':
      return `File or folder already exists: ${error.path}`;
    case 'ENOTDIR':
      return `Not a directory: ${error.path}`;
    case 'EISDIR':
      return `Is a directory, not a file: ${error.path}`;
    case 'ENOTEMPTY':
      return `Directory is not empty: ${error.path}`;
    case 'EMFILE':
      return 'Too many open files';
    case 'ENOSPC':
      return 'No space left on device';
    default:
      return error.message || 'An unknown error occurred';
  }
}

if (process.argv.length > 1) {
  const argPath = process.argv[process.argv.length - 1];
  if (argPath && !argPath.includes('--') && fs.existsSync(argPath)) {
    fileToOpen = argPath;
  }
}

function createWindow() {
  console.log('Creating main window...');
  mainWindow = new BrowserWindow({
    width: 1600,
    height: 1000,
    minWidth: 1200,
    minHeight: 700,
    title: 'Null IDE – NullSec',
    icon: path.join(__dirname, '../../null-ide.png'),
    backgroundColor: '#0a0a0a',
    webPreferences: {
      preload: path.join(__dirname, '../preload/preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      webSecurity: true,
    },
    autoHideMenuBar: true,
    show: false,
  });

  console.log('Window created, loading URL...');

  mainWindow.once('ready-to-show', () => {
    console.log('Window ready, showing...');
    mainWindow?.show();
  });

  if (isDev) {
    console.log('Dev mode: loading http://localhost:5173');
    mainWindow.loadURL('http://localhost:5173').catch((err) => {
      console.error('Failed to load URL:', err);
      setTimeout(() => {
        mainWindow?.loadURL('http://localhost:5173').catch((e) => {
          console.error('Retry failed:', e);
        });
      }, 1000);
    });
  } else {
    console.log('Production mode: loading from file');
    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html')).catch((err) => {
      console.error('Failed to load file:', err);
    });
  }

  mainWindow.webContents.on('did-fail-load', (event, errorCode, errorDescription) => {
    console.error('Page failed to load:', errorCode, errorDescription);
  });

  mainWindow.webContents.on('render-process-gone', (event, details) => {
    console.error('Renderer process gone:', details.reason);
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

function createDeepHatView() {
  if (!mainWindow) return;

  deephatBrowserView = new BrowserView({
    webPreferences: {
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  mainWindow.addBrowserView(deephatBrowserView);
  deephatBrowserView.webContents.loadURL('https://app.deephat.ai/').catch((err) => {
    console.error('Failed to load DeepHat URL:', err);
  });
}

ipcMain.on('position-deephat-view', (event, bounds) => {
  if (deephatBrowserView) {
    deephatBrowserView.setBounds(bounds);
  }
});

ipcMain.on('toggle-deephat-view', (event, show) => {
  if (!mainWindow) return;

  if (show && !deephatBrowserView) {
    createDeepHatView();
  } else if (!show && deephatBrowserView) {
    mainWindow.removeBrowserView(deephatBrowserView);
    deephatBrowserView = null;
  }
});

ipcMain.on('reload-deephat', () => {
  if (deephatBrowserView) {
    deephatBrowserView.webContents.reload();
  }
});

ipcMain.handle('fs:readFile', async (event, filePath: string) => {
  try {
    const content = await fs.promises.readFile(filePath, 'utf-8');
    return { success: true, content };
  } catch (error) {
    return { success: false, error: getUserFriendlyError(error as NodeJS.ErrnoException) };
  }
});

ipcMain.handle('fs:writeFile', async (event, filePath: string, content: string) => {
  try {
    await fs.promises.writeFile(filePath, content, 'utf-8');
    return { success: true };
  } catch (error) {
    return { success: false, error: getUserFriendlyError(error as NodeJS.ErrnoException) };
  }
});

ipcMain.handle('fs:readDir', async (event, dirPath: string) => {
  try {
    const entries = await fs.promises.readdir(dirPath, { withFileTypes: true });
    const limitedEntries = entries.slice(0, 500);
    const items = limitedEntries.map((entry) => ({
      name: entry.name,
      isDirectory: entry.isDirectory(),
      path: path.join(dirPath, entry.name),
    }));
    return { success: true, items, truncated: entries.length > 500 };
  } catch (error) {
    console.error('Error reading directory:', error);
    return { success: false, error: getUserFriendlyError(error as NodeJS.ErrnoException) };
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
  } catch (error) {
    return { success: false, error: getUserFriendlyError(error as NodeJS.ErrnoException) };
  }
});

ipcMain.handle('fs:createFile', async (event, filePath: string) => {
  try {
    await fs.promises.writeFile(filePath, '', 'utf-8');
    return { success: true };
  } catch (error) {
    return { success: false, error: getUserFriendlyError(error as NodeJS.ErrnoException) };
  }
});

ipcMain.handle('fs:createFolder', async (event, folderPath: string) => {
  try {
    await fs.promises.mkdir(folderPath, { recursive: false });
    return { success: true };
  } catch (error) {
    return { success: false, error: getUserFriendlyError(error as NodeJS.ErrnoException) };
  }
});

ipcMain.handle('fs:delete', async (event, itemPath: string) => {
  try {
    const stats = await fs.promises.stat(itemPath);
    if (stats.isDirectory()) {
      await fs.promises.rmdir(itemPath, { recursive: true });
    } else {
      await fs.promises.unlink(itemPath);
    }
    return { success: true };
  } catch (error) {
    return { success: false, error: getUserFriendlyError(error as NodeJS.ErrnoException) };
  }
});

ipcMain.handle('fs:rename', async (event, oldPath: string, newPath: string) => {
  try {
    await fs.promises.rename(oldPath, newPath);
    return { success: true };
  } catch (error) {
    return { success: false, error: getUserFriendlyError(error as NodeJS.ErrnoException) };
  }
});

ipcMain.handle('app:getVersion', () => {
  return app.getVersion();
});

ipcMain.handle('app:getUserDataPath', () => {
  return app.getPath('userData');
});

const DEFAULT_CONFIG: AppConfig = {
  theme: 'dark',
  fontSize: 14,
  tabSize: 2,
  wordWrap: true,
};

ipcMain.handle('config:read', async () => {
  try {
    const configPath = path.join(app.getPath('userData'), 'config.json');
    if (fs.existsSync(configPath)) {
      const content = await fs.promises.readFile(configPath, 'utf-8');

      try {
        const config = JSON.parse(content);
        return { success: true, config: { ...DEFAULT_CONFIG, ...config } };
      } catch (parseError) {
        console.error('Corrupted config file, using defaults:', parseError);
        const backupPath = path.join(app.getPath('userData'), `config.json.backup.${Date.now()}`);
        await fs.promises.copyFile(configPath, backupPath);
        console.log('Backed up corrupted config to:', backupPath);
        return { success: true, config: DEFAULT_CONFIG };
      }
    }
    return { success: true, config: DEFAULT_CONFIG };
  } catch (error) {
    console.error('Error reading config:', error);
    return { success: true, config: DEFAULT_CONFIG };
  }
});

ipcMain.handle('config:write', async (event, config: AppConfig) => {
  try {
    const configPath = path.join(app.getPath('userData'), 'config.json');
    await fs.promises.writeFile(configPath, JSON.stringify(config, null, 2), 'utf-8');
    return { success: true };
  } catch (error) {
    return { success: false, error: getUserFriendlyError(error as NodeJS.ErrnoException) };
  }
});

const ALLOWED_HASH_ALGORITHMS = [
  'md5',
  'sha1',
  'sha256',
  'sha384',
  'sha512',
  'sha3-256',
  'sha3-384',
  'sha3-512',
  'blake2b512',
  'blake2s256',
];

ipcMain.handle('crypto:hash', (event, algorithm: string, data: string) => {
  try {
    const normalizedAlgorithm = algorithm.toLowerCase();
    if (!ALLOWED_HASH_ALGORITHMS.includes(normalizedAlgorithm)) {
      return {
        success: false,
        error: `Invalid hash algorithm. Allowed: ${ALLOWED_HASH_ALGORITHMS.join(', ')}`,
      };
    }

    const hash = crypto.createHash(normalizedAlgorithm).update(data).digest('hex');
    return { success: true, hash };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

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
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('net:reverseDns', async (event, ip: string) => {
  try {
    const hostnames = await dnsReverse(ip);
    return { success: true, hostnames };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('net:httpFetch', async (event, url: string, options: HttpFetchOptions = {}) => {
  try {
    const https = require('https');
    const http = require('http');
    const urlModule = require('url');

    const parsedUrl = urlModule.parse(url);
    const isHttps = parsedUrl.protocol === 'https:';
    const lib = isHttps ? https : http;

    return new Promise<HttpResponse>((resolve) => {
      const requestOptions = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (isHttps ? 443 : 80),
        path: parsedUrl.path,
        method: options.method || 'GET',
        headers: options.headers || {},
        timeout: options.timeout || 10000,
      };

      const req = lib.request(
        requestOptions,
        (
          res: NodeJS.ReadableStream & {
            statusCode?: number;
            statusMessage?: string;
            headers: Record<string, string | string[]>;
          }
        ) => {
          let data = '';
          res.on('data', (chunk: Buffer) => {
            data += chunk.toString();
          });
          res.on('end', () => {
            const headers: Record<string, string> = {};
            Object.keys(res.headers).forEach((key) => {
              const value = res.headers[key];
              headers[key] = Array.isArray(value) ? value.join(', ') : value || '';
            });

            resolve({
              success: true,
              status: res.statusCode,
              statusText: res.statusMessage,
              headers,
              data,
            });
          });
        }
      );

      req.on('error', (error: Error) => {
        resolve({ success: false, error: error.message });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({ success: false, error: 'Request timeout' });
      });

      if (options.body) {
        req.write(options.body);
      }

      req.end();
    });
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('dialog:openFile', async () => {
  if (!mainWindow) {
    return { canceled: true, filePaths: [], error: 'Main window not available' };
  }

  const { dialog } = require('electron');
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openFile'],
    });
    return result;
  } catch (error) {
    return { canceled: true, filePaths: [], error: (error as Error).message };
  }
});

ipcMain.handle('dialog:saveFile', async () => {
  if (!mainWindow) {
    return { canceled: true, filePath: undefined, error: 'Main window not available' };
  }

  const { dialog } = require('electron');
  try {
    const result = await dialog.showSaveDialog(mainWindow, {});
    return result;
  } catch (error) {
    return { canceled: true, filePath: undefined, error: (error as Error).message };
  }
});

ipcMain.handle('dialog:openDirectory', async () => {
  if (!mainWindow) {
    return { canceled: true, filePaths: [], error: 'Main window not available' };
  }

  const { dialog } = require('electron');
  try {
    const result = await dialog.showOpenDialog(mainWindow, {
      properties: ['openDirectory'],
    });
    return result;
  } catch (error) {
    return { canceled: true, filePaths: [], error: (error as Error).message };
  }
});

const terminals = new Map<string, pty.IPty>();

ipcMain.handle('terminal:spawn', (event, terminalId: string, shell?: string, cwd?: string) => {
  try {
    if (!shell) {
      if (process.platform === 'win32') {
        shell = 'powershell.exe';
      } else if (process.platform === 'darwin') {
        shell = '/bin/zsh';
      } else {
        shell = '/bin/bash';
      }
    }

    console.log(`Spawning terminal ${terminalId} with shell ${shell} on ${process.platform}`);

    const ptyProcess = pty.spawn(shell, [], {
      name: 'xterm-256color',
      cols: 80,
      rows: 30,
      cwd: cwd || process.env.HOME || process.cwd(),
      env: process.env as { [key: string]: string },
    });

    if (!ptyProcess || !ptyProcess.pid) {
      throw new Error('Failed to spawn terminal process');
    }

    terminals.set(terminalId, ptyProcess);

    ptyProcess.onData((data: string) => {
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('terminal:data', terminalId, data);
      }
    });

    ptyProcess.onExit((exitInfo: { exitCode: number; signal?: number }) => {
      console.log(`Terminal ${terminalId} exited with code ${exitInfo.exitCode}`);
      if (mainWindow && !mainWindow.isDestroyed()) {
        mainWindow.webContents.send('terminal:exit', terminalId, exitInfo.exitCode);
      }
      terminals.delete(terminalId);
    });

    console.log(`Terminal ${terminalId} spawned successfully with PID ${ptyProcess.pid}`);
    return { success: true, pid: ptyProcess.pid };
  } catch (error) {
    console.error('Error spawning terminal:', error);
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('terminal:write', (event, terminalId: string, data: string) => {
  try {
    const terminal = terminals.get(terminalId);
    if (!terminal) {
      return { success: false, error: 'Terminal not found' };
    }

    terminal.write(data);
    return { success: true };
  } catch (error) {
    console.error('Error writing to terminal:', error);
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('terminal:resize', (_event, terminalId: string, cols: number, rows: number) => {
  try {
    const terminal = terminals.get(terminalId);
    if (terminal) {
      terminal.resize(cols, rows);
      return { success: true };
    }
    return { success: false, error: 'Terminal not found' };
  } catch (error) {
    return { success: false, error: (error as Error).message };
  }
});

ipcMain.handle('terminal:kill', (event, terminalId: string) => {
  const terminal = terminals.get(terminalId);
  if (terminal) {
    terminal.kill();
    terminals.delete(terminalId);
  }
  return { success: true };
});

ipcMain.handle('app:getInitialPath', () => {
  return fileToOpen;
});

app.whenReady().then(() => {
  console.log('App ready, creating window...');
  createWindow();
  console.log('Window created successfully');

  console.log('Initializing Discord RPC...');
  initDiscordRPC();

  setTimeout(() => {
    if (!isDiscordConnected()) {
      console.log('Discord RPC not connected, retrying...');
      initDiscordRPC();
    }
  }, 3000);

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

const gotTheLock = app.requestSingleInstanceLock();
if (!gotTheLock) {
  app.quit();
}

app.on('window-all-closed', () => {
  disconnectDiscordRPC();
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

ipcMain.on('discord:update-activity', (_event, fileName: string | null) => {
  if (fileName) {
    updateActivity('Editing', fileName);
  } else {
    updateActivity('Idling', null);
  }
});
