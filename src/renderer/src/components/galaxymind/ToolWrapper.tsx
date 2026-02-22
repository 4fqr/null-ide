import { ReactNode } from 'react';
import { useStore } from '../../store/store';
import styles from './SharedTool.module.css';

interface ToolWrapperProps {
  title: string;
  icon: ReactNode;
  description?: string;
  children: ReactNode;
}

const ToolWrapper = ({ title, icon, description, children }: ToolWrapperProps) => {
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);

  return (
    <div className={styles.toolWrapper}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <path d="M19 12H5M12 19l-7-7 7-7" />
          </svg>
          Back to Tools
        </button>
        <div className={styles.titleSection}>
          <h2 className={styles.toolTitle}>
            <span className={styles.toolIcon}>{icon}</span>
            {title}
          </h2>
          {description && <p className={styles.toolDescription}>{description}</p>}
        </div>
      </div>
      <div className={styles.toolContent}>{children}</div>
    </div>
  );
};

export default ToolWrapper;
