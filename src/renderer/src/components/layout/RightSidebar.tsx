import React, { useEffect, useRef, useState } from 'react';
import { useStore } from '../../store/store';
import { RobotIcon, RefreshIcon, ExternalLinkIcon } from '../icons/Icons';
import styles from './RightSidebar.module.css';

const DEEPCHAT_URL = 'https://app.deephat.ai/';

const RightSidebar: React.FC = () => {
  const mode = useStore((state) => state.mode);
  const rightSidebarWidth = useStore((state) => state.rightSidebarWidth);
  const setRightSidebarWidth = useStore((state) => state.setRightSidebarWidth);
  const [isResizing, setIsResizing] = useState(false);
  const [iframeKey, setIframeKey] = useState(0);
  const [isLoading, setIsLoading] = useState(true);
  const sidebarRef = useRef<HTMLDivElement>(null);
  const webviewRef = useRef<HTMLWebViewElement>(null);

  const handleResizeMouseDown = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsResizing(true);
    document.body.style.cursor = 'ew-resize';
    document.body.style.userSelect = 'none';
  };

  useEffect(() => {
    if (!isResizing) return;

    const handleMouseMove = (e: MouseEvent) => {
      if (sidebarRef.current) {
        const rect = sidebarRef.current.getBoundingClientRect();
        const newWidth = rect.right - e.clientX;
        if (newWidth >= 300 && newWidth <= 800) {
          setRightSidebarWidth(newWidth);
        }
      }
    };

    const handleMouseUp = () => {
      setIsResizing(false);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };

    document.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseup', handleMouseUp);

    return () => {
      document.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseup', handleMouseUp);
    };
  }, [isResizing, setRightSidebarWidth]);

  useEffect(() => {
    const webview = webviewRef.current;
    if (!webview) return;

    const handleDidStartLoading = () => setIsLoading(true);
    const handleDidStopLoading = () => setIsLoading(false);
    const handleNewWindow = (e: Event) => {
      const customEvent = e as CustomEvent<{ url: string }>;
      if (customEvent.detail?.url) {
        window.open(customEvent.detail.url, '_blank');
      }
    };

    webview.addEventListener('did-start-loading', handleDidStartLoading);
    webview.addEventListener('did-stop-loading', handleDidStopLoading);
    webview.addEventListener('new-window', handleNewWindow);

    return () => {
      webview.removeEventListener('did-start-loading', handleDidStartLoading);
      webview.removeEventListener('did-stop-loading', handleDidStopLoading);
      webview.removeEventListener('new-window', handleNewWindow);
    };
  }, [iframeKey]);

  const handleReload = () => {
    setIsLoading(true);
    setIframeKey((prev) => prev + 1);
  };

  const handleOpenExternal = () => {
    window.open(DEEPCHAT_URL, '_blank');
  };

  return (
    <div className={styles.sidebar} ref={sidebarRef} style={{ width: `${rightSidebarWidth}px` }}>
      <div className={styles.resizeHandle} onMouseDown={handleResizeMouseDown} />

      <div className={styles.header}>
        <div className={styles.title}>
          <span className={styles.icon}>
            <RobotIcon size={20} />
          </span>
          <div className={styles.titleText}>
            <div className={styles.name}>DeepChat AI</div>
            <div className={styles.subtitle}>
              {mode === 'code' ? 'Code Assistant' : 'Security Expert'}
            </div>
          </div>
        </div>
        <div className={styles.headerActions}>
          <button className={styles.actionBtn} onClick={handleReload} title="Reload">
            <RefreshIcon size={16} />
          </button>
          <button className={styles.actionBtn} onClick={handleOpenExternal} title="Open in Browser">
            <ExternalLinkIcon size={16} />
          </button>
        </div>
      </div>

      <div className={styles.browserContainer}>
        {isLoading && (
          <div className={styles.loadingOverlay}>
            <div className={styles.spinner} />
            <span>Loading DeepChat AI...</span>
          </div>
        )}
        <webview
          key={iframeKey}
          ref={webviewRef}
          src={DEEPCHAT_URL}
          className={styles.iframe}
          allowpopups={true}
          style={{ width: '100%', height: '100%', border: 'none', background: '#fff' }}
        />
      </div>

      <div className={styles.footer}>
        <div className={styles.statusDot} />
        <span>Connected to app.deephat.ai</span>
      </div>
    </div>
  );
};

export default RightSidebar;
