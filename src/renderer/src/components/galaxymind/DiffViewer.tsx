import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

interface DiffLine {
  type: 'added' | 'removed' | 'unchanged';
  content: string;
  lineNumber1?: number;
  lineNumber2?: number;
}

const DiffViewer: React.FC = () => {
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);
  const [text1, setText1] = useState('');
  const [text2, setText2] = useState('');
  const [diff, setDiff] = useState<DiffLine[]>([]);

  const calculateDiff = () => {
    const lines1 = text1.split('\n');
    const lines2 = text2.split('\n');
    const result: DiffLine[] = [];

    let i = 0, j = 0;
    
    while (i < lines1.length || j < lines2.length) {
      if (i >= lines1.length) {
        result.push({ type: 'added', content: lines2[j], lineNumber2: j + 1 });
        j++;
      } else if (j >= lines2.length) {
        result.push({ type: 'removed', content: lines1[i], lineNumber1: i + 1 });
        i++;
      } else if (lines1[i] === lines2[j]) {
        result.push({ 
          type: 'unchanged', 
          content: lines1[i], 
          lineNumber1: i + 1, 
          lineNumber2: j + 1 
        });
        i++;
        j++;
      } else {
        // Check if line was modified or removed/added
        const line1InText2 = lines2.slice(j).indexOf(lines1[i]);
        const line2InText1 = lines1.slice(i).indexOf(lines2[j]);

        if (line1InText2 === -1 && line2InText1 === -1) {
          // Lines are different, mark both
          result.push({ type: 'removed', content: lines1[i], lineNumber1: i + 1 });
          result.push({ type: 'added', content: lines2[j], lineNumber2: j + 1 });
          i++;
          j++;
        } else if (line1InText2 !== -1 && (line2InText1 === -1 || line1InText2 < line2InText1)) {
          // Line was removed
          result.push({ type: 'removed', content: lines1[i], lineNumber1: i + 1 });
          i++;
        } else {
          // Line was added
          result.push({ type: 'added', content: lines2[j], lineNumber2: j + 1 });
          j++;
        }
      }
    }

    setDiff(result);
  };

  const getStats = () => {
    const added = diff.filter(d => d.type === 'added').length;
    const removed = diff.filter(d => d.type === 'removed').length;
    const unchanged = diff.filter(d => d.type === 'unchanged').length;
    return { added, removed, unchanged };
  };

  const stats = getStats();

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>🔄</span>
          Diff Viewer
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.splitView}>
          <div className={styles.editorSection}>
            <label className={styles.label}>Original Text</label>
            <textarea
              className={styles.textarea}
              value={text1}
              onChange={(e) => setText1(e.target.value)}
              placeholder="Enter original text..."
              rows={12}
            />
          </div>

          <div className={styles.editorSection}>
            <label className={styles.label}>Modified Text</label>
            <textarea
              className={styles.textarea}
              value={text2}
              onChange={(e) => setText2(e.target.value)}
              placeholder="Enter modified text..."
              rows={12}
            />
          </div>
        </div>

        <div className={styles.actions}>
          <button onClick={calculateDiff} className={styles.button}>
            🔍 Compare
          </button>
        </div>

        {diff.length > 0 && (
          <>
            <div className={styles.diffStats}>
              <span className={styles.statAdded}>+{stats.added} added</span>
              <span className={styles.statRemoved}>-{stats.removed} removed</span>
              <span className={styles.statUnchanged}>={stats.unchanged} unchanged</span>
            </div>

            <div className={styles.diffContainer}>
              {diff.map((line, index) => (
                <div 
                  key={index}
                  className={`${styles.diffLine} ${styles[`diff${line.type.charAt(0).toUpperCase() + line.type.slice(1)}`]}`}
                >
                  <span className={styles.lineNumbers}>
                    <span className={styles.lineNumber}>{line.lineNumber1 || ' '}</span>
                    <span className={styles.lineNumber}>{line.lineNumber2 || ' '}</span>
                  </span>
                  <span className={styles.diffContent}>
                    <span className={styles.diffMarker}>
                      {line.type === 'added' ? '+' : line.type === 'removed' ? '-' : ' '}
                    </span>
                    {line.content}
                  </span>
                </div>
              ))}
            </div>
          </>
        )}
      </div>
    </div>
  );
};

export default DiffViewer;
