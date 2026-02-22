import React, { useState, useRef, useEffect } from 'react';
import { useStore } from '../../store/store';
import styles from './FileExplorer.module.css';

interface FileItem {
  name: string;
  path: string;
  isDirectory: boolean;
  children?: FileItem[];
  expanded?: boolean;
  selected?: boolean;
}

const FileIcon = () => (
  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <polyline points="14 2 14 8 20 8" />
  </svg>
);

const FolderIcon = ({ open = false }) => (
  <svg
    width="16"
    height="16"
    viewBox="0 0 24 24"
    fill={open ? 'currentColor' : 'none'}
    stroke="currentColor"
    strokeWidth="2"
  >
    {open ? (
      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
    ) : (
      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
    )}
  </svg>
);

const NewFileIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
    <polyline points="14 2 14 8 20 8" />
    <line x1="12" y1="18" x2="12" y2="12" />
    <line x1="9" y1="15" x2="15" y2="15" />
  </svg>
);

const NewFolderIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
    <line x1="12" y1="11" x2="12" y2="17" />
    <line x1="9" y1="14" x2="15" y2="14" />
  </svg>
);

const OpenFolderIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2v1" />
    <path d="M2 10h20" />
  </svg>
);

const RefreshIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
    <polyline points="23 4 23 10 17 10" />
    <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
  </svg>
);

const pathJoin = (...parts: string[]): string => {
  return parts
    .map((part, i) => {
      if (i === 0) return part.replace(/[/\\]+$/, '');
      return part.replace(/^[/\\]+|[/\\]+$/g, '');
    })
    .join('/');
};

const getFileExtension = (fileName: string): string => {
  return fileName.split('.').pop()?.toLowerCase() || '';
};

const getFileIconComponent = (fileName: string, isDirectory: boolean): React.ReactNode => {
  if (isDirectory) return <FolderIcon />;

  const ext = getFileExtension(fileName);
  const iconColors: Record<string, string> = {
    js: '#f7df1e',
    jsx: '#61dafb',
    ts: '#3178c6',
    tsx: '#3178c6',
    py: '#3776ab',
    html: '#e34f26',
    css: '#1572b6',
    scss: '#cc6699',
    json: '#292929',
    md: '#083fa1',
    txt: '#6b7280',
    go: '#00add8',
    rs: '#dea584',
    java: '#b07219',
    php: '#777bb4',
    rb: '#cc342d',
    swift: '#f05138',
    cpp: '#00599c',
    c: '#a8b9cc',
    sh: '#4eaa25',
    bash: '#4eaa25',
    sql: '#e38c00',
    yaml: '#cb171e',
    yml: '#cb171e',
    xml: '#e37933',
    vue: '#42b883',
    svelte: '#ff3e00',
  };

  const color = iconColors[ext] || 'var(--color-accent)';
  return <FileIcon />;
};

const FileExplorer: React.FC = () => {
  const [rootPath, setRootPath] = useState('');
  const [fileTree, setFileTree] = useState<FileItem[]>([]);
  const [showNewFileDialog, setShowNewFileDialog] = useState(false);
  const [showNewFolderDialog, setShowNewFolderDialog] = useState(false);
  const [newItemName, setNewItemName] = useState('');
  const [selectedPath, setSelectedPath] = useState<string>('');
  const [contextMenu, setContextMenu] = useState<{
    x: number;
    y: number;
    path: string;
    isDirectory: boolean;
  } | null>(null);
  const contextMenuRef = useRef<HTMLDivElement>(null);
  const openTab = useStore((state) => state.openTab);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) {
        setContextMenu(null);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleOpenDirectory = async () => {
    const result = await window.electronAPI.dialog.openDirectory();
    if (!result.canceled && result.filePaths[0]) {
      const dirPath = result.filePaths[0];
      setRootPath(dirPath);
      setSelectedPath(dirPath);
      await loadDirectory(dirPath, null);
    }
  };

  const handleRefresh = async () => {
    if (rootPath) {
      await loadDirectory(rootPath, null);
    }
  };

  const handleNewFile = (targetPath?: string) => {
    if (!rootPath) return;
    setSelectedPath(targetPath || selectedPath || rootPath);
    setShowNewFileDialog(true);
    setNewItemName('');
    setContextMenu(null);
  };

  const handleNewFolder = (targetPath?: string) => {
    if (!rootPath) return;
    setSelectedPath(targetPath || selectedPath || rootPath);
    setShowNewFolderDialog(true);
    setNewItemName('');
    setContextMenu(null);
  };

  const createNewFile = async () => {
    if (!newItemName.trim()) return;

    const targetPath = selectedPath || rootPath;
    const filePath = pathJoin(targetPath, newItemName);

    const result = await window.electronAPI.fs.createFile(filePath);
    if (result.success) {
      const ext = getFileExtension(newItemName);
      const languageMap: Record<string, string> = {
        js: 'javascript',
        jsx: 'javascript',
        ts: 'typescript',
        tsx: 'typescript',
        py: 'python',
        html: 'html',
        css: 'css',
        scss: 'scss',
        json: 'json',
        md: 'markdown',
        txt: 'plaintext',
        xml: 'xml',
        yaml: 'yaml',
        yml: 'yaml',
        sh: 'shell',
        bash: 'shell',
        sql: 'sql',
        cpp: 'cpp',
        c: 'c',
        java: 'java',
        php: 'php',
        rb: 'ruby',
        go: 'go',
        rs: 'rust',
      };

      openTab({
        id: `file-${Date.now()}`,
        path: filePath,
        name: newItemName,
        language: languageMap[ext] || 'plaintext',
        content: '',
        modified: false,
      });

      setShowNewFileDialog(false);
      setNewItemName('');
      await loadDirectory(rootPath, null);
    } else {
      alert(`Failed to create file: ${result.error}`);
    }
  };

  const createNewFolder = async () => {
    if (!newItemName.trim()) return;

    const targetPath = selectedPath || rootPath;
    const folderPath = pathJoin(targetPath, newItemName);

    const result = await window.electronAPI.fs.createFolder(folderPath);
    if (result.success) {
      setShowNewFolderDialog(false);
      setNewItemName('');
      await loadDirectory(rootPath, null);
    } else {
      alert(`Failed to create folder: ${result.error}`);
    }
  };

  const handleDelete = async (path: string, isDirectory: boolean) => {
    const confirmDelete = confirm(
      `Are you sure you want to delete this ${isDirectory ? 'folder' : 'file'}?`
    );
    if (!confirmDelete) return;

    try {
      if (isDirectory) {
        await window.electronAPI.fs.deleteFolder(path);
      } else {
        await window.electronAPI.fs.deleteFile(path);
      }
      await loadDirectory(rootPath, null);
    } catch (error) {
      alert(`Failed to delete: ${error}`);
    }
    setContextMenu(null);
  };

  const handleRename = async (path: string, oldName: string) => {
    const newName = prompt('Enter new name:', oldName);
    if (!newName || newName === oldName) return;

    const parentPath = path.substring(0, path.lastIndexOf('/'));
    const newPath = pathJoin(parentPath, newName);

    try {
      await window.electronAPI.fs.rename(path, newPath);
      await loadDirectory(rootPath, null);
    } catch (error) {
      alert(`Failed to rename: ${error}`);
    }
    setContextMenu(null);
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

        const items: FileItem[] = sorted.map((item) => ({
          name: item.name,
          path: item.path,
          isDirectory: item.isDirectory,
          children: item.isDirectory ? [] : undefined,
          expanded: false,
        }));

        if (parentIndex === null) {
          setFileTree(items);
        } else {
          setFileTree((prev) => updateTreeAtPath(prev, parentIndex, items));
        }
      }
    } catch (error) {
      console.error('Failed to load directory:', error);
    }
  };

  const updateTreeAtPath = (
    tree: FileItem[],
    indices: number[],
    newChildren: FileItem[]
  ): FileItem[] => {
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
      await loadDirectory(item.path, indices);
    } else {
      setFileTree((prev) => toggleExpandedAtPath(prev, indices));
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
    if (item.isDirectory) {
      setSelectedPath(item.path);
      return;
    }

    try {
      const result = await window.electronAPI.fs.readFile(item.path);
      if (result.success && result.content) {
        const ext = getFileExtension(item.name);
        const languageMap: Record<string, string> = {
          js: 'javascript',
          jsx: 'javascript',
          ts: 'typescript',
          tsx: 'typescript',
          py: 'python',
          html: 'html',
          css: 'css',
          scss: 'scss',
          json: 'json',
          md: 'markdown',
          txt: 'plaintext',
          xml: 'xml',
          yaml: 'yaml',
          yml: 'yaml',
          sh: 'shell',
          bash: 'shell',
          sql: 'sql',
          cpp: 'cpp',
          c: 'c',
          java: 'java',
          php: 'php',
          rb: 'ruby',
          go: 'go',
          rs: 'rust',
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

  const handleContextMenu = (e: React.MouseEvent, item: FileItem) => {
    e.preventDefault();
    e.stopPropagation();
    setContextMenu({
      x: e.clientX,
      y: e.clientY,
      path: item.path,
      isDirectory: item.isDirectory,
    });
    setSelectedPath(item.path);
  };

  const handleBackgroundContextMenu = (e: React.MouseEvent) => {
    e.preventDefault();
    setContextMenu({
      x: e.clientX,
      y: e.clientY,
      path: rootPath,
      isDirectory: true,
    });
    setSelectedPath(rootPath);
  };

  const renderTree = (
    items: FileItem[],
    depth: number = 0,
    parentIndices: number[] = []
  ): React.ReactNode => {
    return items.map((item, index) => {
      const currentIndices = [...parentIndices, index];
      const isExpanded = item.expanded;
      const isSelected = item.path === selectedPath;

      return (
        <div key={item.path}>
          <div
            className={`${styles.fileItem} ${isSelected ? styles.selected : ''}`}
            style={{ paddingLeft: `${depth * 12 + 10}px` }}
            onClick={() =>
              item.isDirectory ? toggleFolder(currentIndices) : handleFileClick(item)
            }
            onContextMenu={(e) => handleContextMenu(e, item)}
            title={item.path}
          >
            {item.isDirectory && (
              <span className={styles.arrow}>
                <svg
                  width="10"
                  height="10"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  style={{
                    transform: isExpanded ? 'rotate(90deg)' : 'rotate(0deg)',
                    transition: 'transform 0.15s ease',
                  }}
                >
                  <polyline points="9 18 15 12 9 6" />
                </svg>
              </span>
            )}
            {!item.isDirectory && <span className={styles.arrowPlaceholder} />}
            <span className={styles.fileIcon}>
              {item.isDirectory ? (
                <FolderIcon open={isExpanded} />
              ) : (
                getFileIconComponent(item.name, false)
              )}
            </span>
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
          <OpenFolderIcon />
          <span>Open</span>
        </button>
        {rootPath && (
          <>
            <button className={styles.btnIcon} onClick={handleRefresh} title="Refresh">
              <RefreshIcon />
            </button>
            <button
              className={styles.btnSecondary}
              onClick={() => handleNewFile()}
              title="New File"
            >
              <NewFileIcon />
              <span>File</span>
            </button>
            <button
              className={styles.btnSecondary}
              onClick={() => handleNewFolder()}
              title="New Folder"
            >
              <NewFolderIcon />
              <span>Folder</span>
            </button>
          </>
        )}
      </div>

      {rootPath && (
        <div className={styles.currentPath} title={rootPath}>
          <FolderIcon open />
          <span>{rootPath.split(/[/\\]/).pop() || rootPath}</span>
        </div>
      )}

      <div className={styles.fileList} onContextMenu={handleBackgroundContextMenu}>
        {fileTree.length === 0 && !rootPath ? (
          <div className={styles.empty}>
            <p>No folder opened</p>
            <small>Click "Open" to browse a directory</small>
          </div>
        ) : fileTree.length === 0 ? (
          <div className={styles.empty}>
            <p>Empty folder</p>
            <small>Right-click to create files or folders</small>
          </div>
        ) : (
          renderTree(fileTree)
        )}
      </div>

      {contextMenu && (
        <div
          ref={contextMenuRef}
          className={styles.contextMenu}
          style={{ left: contextMenu.x, top: contextMenu.y }}
        >
          {contextMenu.isDirectory && (
            <>
              <button onClick={() => handleNewFile(contextMenu.path)}>
                <NewFileIcon /> New File
              </button>
              <button onClick={() => handleNewFolder(contextMenu.path)}>
                <NewFolderIcon /> New Folder
              </button>
              <div className={styles.separator} />
            </>
          )}
          <button
            onClick={() => handleRename(contextMenu.path, contextMenu.path.split('/').pop() || '')}
          >
            Rename
          </button>
          <button
            onClick={() => handleDelete(contextMenu.path, contextMenu.isDirectory)}
            className={styles.danger}
          >
            Delete
          </button>
        </div>
      )}

      {showNewFileDialog && (
        <div className={styles.dialogOverlay} onClick={() => setShowNewFileDialog(false)}>
          <div className={styles.dialog} onClick={(e) => e.stopPropagation()}>
            <h3>Create New File</h3>
            <p className={styles.dialogPath}>in: {selectedPath || rootPath}</p>
            <input
              type="text"
              value={newItemName}
              onChange={(e) => setNewItemName(e.target.value)}
              placeholder="filename.txt"
              autoFocus
              onKeyDown={(e) => {
                if (e.key === 'Enter') createNewFile();
                if (e.key === 'Escape') setShowNewFileDialog(false);
              }}
            />
            <div className={styles.dialogButtons}>
              <button onClick={() => setShowNewFileDialog(false)}>Cancel</button>
              <button onClick={createNewFile} className={styles.primary}>
                Create
              </button>
            </div>
          </div>
        </div>
      )}

      {showNewFolderDialog && (
        <div className={styles.dialogOverlay} onClick={() => setShowNewFolderDialog(false)}>
          <div className={styles.dialog} onClick={(e) => e.stopPropagation()}>
            <h3>Create New Folder</h3>
            <p className={styles.dialogPath}>in: {selectedPath || rootPath}</p>
            <input
              type="text"
              value={newItemName}
              onChange={(e) => setNewItemName(e.target.value)}
              placeholder="folder-name"
              autoFocus
              onKeyDown={(e) => {
                if (e.key === 'Enter') createNewFolder();
                if (e.key === 'Escape') setShowNewFolderDialog(false);
              }}
            />
            <div className={styles.dialogButtons}>
              <button onClick={() => setShowNewFolderDialog(false)}>Cancel</button>
              <button onClick={createNewFolder} className={styles.primary}>
                Create
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FileExplorer;
