import React, { useEffect, useRef, useState } from 'react';
import { useStore } from '../../store/store';
import { RobotIcon, RefreshIcon } from '../icons/Icons';
import styles from './RightSidebar.module.css';

const RightSidebar: React.FC = () => {
  const mode = useStore((state) => state.mode);
  const rightSidebarWidth = useStore((state) => state.rightSidebarWidth);
  const setRightSidebarWidth = useStore((state) => state.setRightSidebarWidth);
  const [isResizing, setIsResizing] = useState(false);
  const containerRef = useRef<HTMLDivElement>(null);
  const sidebarRef = useRef<HTMLDivElement>(null);

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
    const updatePosition = () => {
      if (containerRef.current && sidebarRef.current && window.electronAPI?.deephat) {
        const rect = containerRef.current.getBoundingClientRect();

        window.electronAPI.deephat.position({
          x: Math.floor(rect.left) + 30,
          y: Math.floor(rect.top),
          width: Math.floor(rect.width) - 30,
          height: Math.floor(rect.height),
        });
      }
    };

    updatePosition();
    if (window.electronAPI?.deephat) {
      window.electronAPI.deephat.toggle(true);
    }

    const resizeObserver = new ResizeObserver(updatePosition);
    if (containerRef.current) {
      resizeObserver.observe(containerRef.current);
    }

    return () => {
      resizeObserver.disconnect();
      if (window.electronAPI?.deephat) {
        window.electronAPI.deephat.toggle(false);
      }
    };
  }, []);

  const handleReload = () => {
    if (window.electronAPI?.deephat) {
      window.electronAPI.deephat.reload();
    }
  };

  return (
    <div className={styles.sidebar} ref={sidebarRef} style={{ width: `${rightSidebarWidth}px` }}>
      <div className={styles.resizeHandle} onMouseDown={handleResizeMouseDown} />

      <div className={styles.header}>
        <div className={styles.title}>
          <span className={styles.icon}>
            <RobotIcon size={24} />
          </span>
          <div className={styles.titleText}>
            <div className={styles.name}>DeepHat AI</div>
            <div className={styles.subtitle}>
              {mode === 'code' ? 'Code Assistant' : 'Security Expert'}
            </div>
          </div>
        </div>
        <button className={styles.reloadBtn} onClick={handleReload} title="Reload">
          <RefreshIcon size={18} />
        </button>
      </div>

      <div ref={containerRef} className={styles.browserContainer}></div>

      <div className={styles.disclaimer}>
        <small>External content from app.deephat.ai</small>
      </div>
    </div>
  );
};

export default RightSidebar;
