import { useState } from 'react';
import { useStore } from '../../store/store';
import {
  FolderIcon,
  FolderOpenIcon,
  FileIcon,
  ChevronRightIcon,
  ChevronDownIcon,
  PythonFileIcon,
  JavaScriptFileIcon,
  TypeScriptFileIcon,
  JsonFileIcon,
  MarkdownFileIcon,
  ConfigFileIcon,
  ImageFileIcon,
  DockerFileIcon,
  GitIgnoreFileIcon,
  CSSFileIcon,
  HTMLFileIcon,
  YAMLFileIcon,
  BashFileIcon,
  SQLFileIcon,
} from '../common/Icons';
import styles from './FileExplorer.module.css';

interface FileItem {
  name: string;
  path: string;
  isDirectory: boolean;
  children?: FileItem[];
  expanded?: boolean;
}

const FileExplorer = () => {
  const [rootPath, setRootPath] = useState('');
  const [fileTree, setFileTree] = useState<FileItem[]>([]);
  const [expandedPaths, setExpandedPaths] = useState<Set<string>>(new Set());
  const openTab = useStore((state) => state.openTab);
  const setMode = useStore((state) => state.setMode);

  const getFileIcon = (fileName: string, isDirectory: boolean, isOpen: boolean) => {
    if (isDirectory) {
      return isOpen ? <FolderOpenIcon size={16} /> : <FolderIcon size={16} />;
    }

    const ext = fileName.split('.').pop()?.toLowerCase() || '';
    const name = fileName.toLowerCase();

    if (
      name === 'dockerfile' ||
      name === '.dockerignore' ||
      name === 'docker-compose.yml' ||
      name === 'docker-compose.yaml'
    ) {
      return <DockerFileIcon />;
    }
    if (name === '.gitignore' || name === '.gitattributes') {
      return <GitIgnoreFileIcon />;
    }
    if (
      name.startsWith('.env') ||
      name === '.editorconfig' ||
      name === '.prettierrc' ||
      name === '.eslintrc'
    ) {
      return <ConfigFileIcon />;
    }

    const iconMap: Record<string, React.ReactNode> = {
      js: <JavaScriptFileIcon />,
      jsx: <JavaScriptFileIcon />,
      ts: <TypeScriptFileIcon />,
      tsx: <TypeScriptFileIcon />,
      py: <PythonFileIcon />,
      json: <JsonFileIcon />,
      md: <MarkdownFileIcon />,
      css: <CSSFileIcon />,
      scss: <CSSFileIcon />,
      sass: <CSSFileIcon />,
      less: <CSSFileIcon />,
      html: <HTMLFileIcon />,
      htm: <HTMLFileIcon />,
      yaml: <YAMLFileIcon />,
      yml: <YAMLFileIcon />,
      sh: <BashFileIcon />,
      bash: <BashFileIcon />,
      zsh: <BashFileIcon />,
      sql: <SQLFileIcon />,
      png: <ImageFileIcon />,
      jpg: <ImageFileIcon />,
      jpeg: <ImageFileIcon />,
      gif: <ImageFileIcon />,
      svg: <ImageFileIcon />,
      webp: <ImageFileIcon />,
      ico: <ImageFileIcon />,
      toml: <ConfigFileIcon />,
      ini: <ConfigFileIcon />,
      cfg: <ConfigFileIcon />,
      conf: <ConfigFileIcon />,
      config: <ConfigFileIcon />,
      xml: <ConfigFileIcon />,
      txt: <FileIcon size={16} />,
      lock: <FileIcon size={16} />,
    };

    return iconMap[ext] || <FileIcon size={16} />;
  };

  const handleOpenDirectory = async () => {
    try {
      const result = await window.electronAPI.dialog.openDirectory();
      if (!result.canceled && result.filePaths[0]) {
        const dirPath = result.filePaths[0];
        setRootPath(dirPath);
        setExpandedPaths(new Set());
        await loadDirectory(dirPath, null);
      }
    } catch (err) {
      console.error('Failed to open directory:', err);
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

    const isExpanded = expandedPaths.has(item.path);

    if (!isExpanded && (!item.children || item.children.length === 0)) {
      await loadDirectory(item.path, indices);
      setExpandedPaths((prev) => new Set(prev).add(item.path));
    } else {
      setFileTree((prev) => toggleExpandedAtPath(prev, indices));
      if (isExpanded) {
        setExpandedPaths((prev) => {
          const newSet = new Set(prev);
          newSet.delete(item.path);
          return newSet;
        });
      } else {
        setExpandedPaths((prev) => new Set(prev).add(item.path));
      }
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
      if (result.success && result.content !== undefined) {
        const ext = item.name.split('.').pop()?.toLowerCase() || 'txt';
        const languageMap: Record<string, string> = {
          js: 'javascript',
          jsx: 'javascript',
          ts: 'typescript',
          tsx: 'typescript',
          py: 'python',
          html: 'html',
          htm: 'html',
          css: 'css',
          scss: 'scss',
          sass: 'sass',
          less: 'less',
          json: 'json',
          md: 'markdown',
          txt: 'plaintext',
          xml: 'xml',
          yaml: 'yaml',
          yml: 'yaml',
          sh: 'shell',
          bash: 'shell',
          zsh: 'shell',
          sql: 'sql',
          cpp: 'cpp',
          cc: 'cpp',
          cxx: 'cpp',
          c: 'c',
          h: 'c',
          java: 'java',
          php: 'php',
          go: 'go',
          rs: 'rust',
          rb: 'ruby',
          swift: 'swift',
          kt: 'kotlin',
          scala: 'scala',
          r: 'r',
          lua: 'lua',
          pl: 'perl',
          pm: 'perl',
          hs: 'haskell',
          ex: 'elixir',
          exs: 'elixir',
          dart: 'dart',
          toml: 'ini',
          ini: 'ini',
          cfg: 'ini',
          conf: 'ini',
          dockerfile: 'dockerfile',
          makefile: 'makefile',
        };

        const newTab = {
          id: `file-${Date.now()}`,
          name: item.name,
          path: item.path,
          content: result.content,
          originalContent: result.content,
          language: languageMap[ext] || 'plaintext',
          modified: false,
        };

        openTab(newTab);
        setMode('code');
      }
    } catch (error) {
      console.error('Failed to open file:', error);
    }
  };

  const renderTree = (
    items: FileItem[],
    depth = 0,
    parentIndices: number[] = []
  ): React.ReactNode => {
    return items.map((item, index) => {
      const currentIndices = [...parentIndices, index];
      const isExpanded = item.isDirectory && (item.expanded || expandedPaths.has(item.path));

      return (
        <div key={item.path}>
          <div
            className={styles.fileItem}
            onClick={() =>
              item.isDirectory ? toggleFolder(currentIndices) : handleFileClick(item)
            }
          >
            <span className={styles.arrow}>
              {item.isDirectory ? (
                isExpanded ? (
                  <ChevronDownIcon size={14} />
                ) : (
                  <ChevronRightIcon size={14} />
                )
              ) : (
                <span style={{ width: 14, display: 'inline-block' }} />
              )}
            </span>
            <span className={styles.fileIcon}>
              {getFileIcon(item.name, item.isDirectory, isExpanded)}
            </span>
            <span className={styles.fileName}>{item.name}</span>
          </div>
          {isExpanded && item.children && item.children.length > 0 && (
            <div className={styles.childrenContainer} style={{ paddingLeft: 12 }}>
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
        <button className={styles.btnPrimary} onClick={handleOpenDirectory}>
          Open Folder
        </button>
      </div>

      {rootPath && (
        <div className={styles.currentPath}>{rootPath.split(/[/\\]/).pop() || rootPath}</div>
      )}

      <div className={styles.fileList}>
        {fileTree.length === 0 && !rootPath ? (
          <div className={styles.empty}>
            <p>No folder opened</p>
            <small>Click "Open Folder" to start</small>
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
