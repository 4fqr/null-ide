import React from 'react';
import MainEditorArea from '../layout/MainEditorArea';
import styles from './DeepZero.module.css';

const DeepZero: React.FC = () => {
  return (
    <div className={styles.deepZero}>
      <MainEditorArea />
    </div>
  );
};

export default DeepZero;
