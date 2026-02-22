import React from 'react';
import { useStore } from '../../store/store';
import ThemeExtensions from '../extensions/ThemeExtensions';
import styles from './ThemeModal.module.css';

const ThemeModal: React.FC = () => {
  const { themesOpen, closeThemes } = useStore();

  if (!themesOpen) return null;

  return (
    <div className={styles.overlay} onClick={closeThemes}>
      <div className={styles.modal} onClick={(e) => e.stopPropagation()}>
        <div className={styles.header}>
          <h2>Theme Extensions</h2>
          <button className={styles.closeBtn} onClick={closeThemes}>
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12"/>
            </svg>
          </button>
        </div>
        <div className={styles.content}>
          <ThemeExtensions />
        </div>
      </div>
    </div>
  );
};

export default ThemeModal;
