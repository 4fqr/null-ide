import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './FileExplorer.module.css';

interface FileItem {
  name: string;
  path: string;
  isDirectory: boolean;
  children?: FileItem[];
  expanded?: boolean;
}

// File type to icon mapping
const getFileIcon = (fileName: string, isDirectory: boolean): string => {
  if (isDirectory) return '📁';
  
  const ext = fileName.split('.').pop()?.toLowerCase() || '';
  const iconMap: Record<string, string> = {
    // JavaScript/TypeScript
    js: '📜', jsx: '⚛️', ts: '📘', tsx: '⚛️', mjs: '📜', cjs: '📜',
    // Python
    py: '🐍', pyw: '🐍', pyc: '🐍', pyd: '🐍',
    // Java/JVM
    java: '☕', jar: '☕', class: '☕', kt: '🟣', scala: '🔴',
    // C/C++
    c: '⚙️', cpp: '⚙️', cxx: '⚙️', cc: '⚙️', h: '⚙️', hpp: '⚙️', hxx: '⚙️',
    // C#/.NET
    cs: '#️⃣', csx: '#️⃣', vb: '#️⃣', fs: '#️⃣',
    // Other languages
    go: '🐹', rs: '🦀', php: '🐘', rb: '💎', swift: '🦅', lua: '🌙',
    r: '📊', dart: '🎯', elixir: '💧', ex: '💧', exs: '💧',
    // Web
    html: '🌐', htm: '🌐', css: '🎨', scss: '🎨', sass: '🎨', less: '🎨',
    vue: '💚', svelte: '🧡',
    // Data formats
    json: '📋', xml: '📋', yaml: '📋', yml: '📋', toml: '📋', ini: '📋',
    csv: '📊', tsv: '📊',
    // Docs
    md: '📝', markdown: '📝', txt: '📄', pdf: '📕', doc: '📄', docx: '📄',
    // Images
    png: '🖼️', jpg: '🖼️', jpeg: '🖼️', gif: '🖼️', svg: '🎨', ico: '🖼️',
    bmp: '🖼️', webp: '🖼️',
    // Shell/Config
    sh: '🔧', bash: '🔧', zsh: '🔧', fish: '🔧', ps1: '🔧',
    env: '⚙️', config: '⚙️', conf: '⚙️',
    // Build/Package
    dockerfile: '🐳', makefile: '🔨', cmake: '🔨',
    'package.json': '📦', 'package-lock.json': '🔒',
    // Databases
    sql: '🗄️', db: '🗄️', sqlite: '🗄️',
  };
  
  // Check exact filename matches first
  const lowerName = fileName.toLowerCase();
  if (iconMap[lowerName]) return iconMap[lowerName];
  
  return iconMap[ext] || '📄';
};

const FileExplorer: React.FC = () => {
  const [rootPath, setRootPath] = useState('');
  const [fileTree, setFileTree] = useState<FileItem[]>([]);
  const openTab = useStore((state) => state.openTab);

  const handleOpenDirectory = async () => {
    const result = await window.electronAPI.dialog.openDirectory();
    if (!result.canceled && result.filePaths[0]) {
      const dirPath = result.filePaths[0];
      setRootPath(dirPath);
      await loadDirectory(dirPath, null);
    }
  };

  const loadDirectory = async (path: string, parentIndex: number[] | null) => {
    try {
      const result = await window.electronAPI.fs.readDir(path);
      if (result.success && result.items) {
        const sorted = result.items.sort((a, b) => {
          if (a.isDirectory && !b.isDirectory) return -1;
          if (!a.isDirectory && b.isDirectory) return 1;
          return a.name.localeCompare(b.name);
        });

        const items: FileItem[] = sorted.map(item => ({
          name: item.name,
          path: item.path,
          isDirectory: item.isDirectory,
          children: item.isDirectory ? [] : undefined,
          expanded: false,
        }));

        if (parentIndex === null) {
          // Root level
          setFileTree(items);
        } else {
          // Nested level - update specific folder
          setFileTree(prev => updateTreeAtPath(prev, parentIndex, items));
        }
      }
    } catch (error) {
      console.error('Failed to load directory:', error);
    }
  };

  const updateTreeAtPath = (tree: FileItem[], indices: number[], newChildren: FileItem[]): FileItem[] => {
    if (indices.length === 0) return tree;
    
    const [currentIndex, ...restIndices] = indices;
    return tree.map((item, idx) => {
      if (idx !== currentIndex) return item;
      
      if (restIndices.length === 0) {
        return { ...item, children: newChildren, expanded: true };
      }
      
      return {
        ...item,
        children: item.children ? updateTreeAtPath(item.children, restIndices, newChildren) : [],
      };
    });
  };

  const toggleFolder = async (indices: number[]) => {
    const item = getItemAtPath(fileTree, indices);
    if (!item || !item.isDirectory) return;

    if (!item.expanded && (!item.children || item.children.length === 0)) {
      // Load children
      await loadDirectory(item.path, indices);
    } else {
      // Just toggle expanded state
      setFileTree(prev => toggleExpandedAtPath(prev, indices));
    }
  };

  const toggleExpandedAtPath = (tree: FileItem[], indices: number[]): FileItem[] => {
    if (indices.length === 0) return tree;
    
    const [currentIndex, ...restIndices] = indices;
    return tree.map((item, idx) => {
      if (idx !== currentIndex) return item;
      
      if (restIndices.length === 0) {
        return { ...item, expanded: !item.expanded };
      }
      
      return {
        ...item,
        children: item.children ? toggleExpandedAtPath(item.children, restIndices) : [],
      };
    });
  };

  const getItemAtPath = (tree: FileItem[], indices: number[]): FileItem | null => {
    if (indices.length === 0) return null;
    
    const [currentIndex, ...restIndices] = indices;
    const item = tree[currentIndex];
    if (!item) return null;
    
    if (restIndices.length === 0) return item;
    return item.children ? getItemAtPath(item.children, restIndices) : null;
  };

  const handleFileClick = async (item: FileItem) => {
    if (item.isDirectory) return;

    try {
      const result = await window.electronAPI.fs.readFile(item.path);
      if (result.success && result.content) {
        const ext = item.name.split('.').pop()?.toLowerCase() || 'txt';
        const languageMap: Record<string, string> = {
          js: 'javascript', jsx: 'javascript', ts: 'typescript', tsx: 'typescript',
          py: 'python', html: 'html', css: 'css', scss: 'scss', json: 'json',
          md: 'markdown', txt: 'plaintext', xml: 'xml', yaml: 'yaml', yml: 'yaml',
          sh: 'shell', bash: 'shell', sql: 'sql', cpp: 'cpp', c: 'c', java: 'java',
          php: 'php', rb: 'ruby', go: 'go', rs: 'rust',
        };

        openTab({
          id: `file-${Date.now()}`,
          path: item.path,
          name: item.name,
          language: languageMap[ext] || 'plaintext',
          content: result.content,
          modified: false,
        });
      }
    } catch (error) {
      console.error('Failed to open file:', error);
    }
  };

  const renderTree = (items: FileItem[], depth: number = 0, parentIndices: number[] = []): React.ReactNode => {
    return items.map((item, index) => {
      const currentIndices = [...parentIndices, index];
      const isExpanded = item.expanded;
      
      return (
        <div key={item.path}>
          <div
            className={styles.fileItem}
            style={{ paddingLeft: `${depth * 12 + 10}px` }}
            onClick={() => item.isDirectory ? toggleFolder(currentIndices) : handleFileClick(item)}
            title={item.path}
          >
            {item.isDirectory && (
              <span className={styles.arrow}>
                {isExpanded ? '▾' : '▸'}
              </span>
            )}
            <span className={styles.fileIcon}>{getFileIcon(item.name, item.isDirectory)}</span>
            <span className={styles.fileName}>{item.name}</span>
          </div>
          {item.isDirectory && isExpanded && item.children && item.children.length > 0 && (
            <div className={styles.childrenContainer}>
              {renderTree(item.children, depth + 1, currentIndices)}
            </div>
          )}
        </div>
      );
    });
  };

  return (
    <div className={styles.explorer}>
      <div className={styles.toolbar}>
        <button className={styles.btnPrimary} onClick={handleOpenDirectory} title="Open Folder">
          📂 Open
        </button>
      </div>

      {rootPath && (
        <div className={styles.currentPath} title={rootPath}>
          📁 {rootPath.split(/[/\\]/).pop() || rootPath}
        </div>
      )}

      <div className={styles.fileList}>
        {fileTree.length === 0 && !rootPath ? (
          <div className={styles.empty}>
            <p>No folder opened</p>
            <small>Click &quot;Open&quot; to start</small>
          </div>
        ) : fileTree.length === 0 ? (
          <div className={styles.empty}>
            <p>Empty folder</p>
          </div>
        ) : (
          renderTree(fileTree)
        )}
      </div>
    </div>
  );
};

export default FileExplorer;
