import React, { useState } from 'react';
import { useStore } from '../../store/store';
import styles from './GalaxyTool.module.css';

const MarkdownPreview: React.FC = () => {
  const setActiveGalaxyTool = useStore((state) => state.setActiveGalaxyTool);
  const [markdown, setMarkdown] = useState('');

  const renderMarkdown = (text: string): string => {
    let html = text;

    // Headers
    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    // Bold
    html = html.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
    html = html.replace(/__(.*?)__/gim, '<strong>$1</strong>');

    // Italic
    html = html.replace(/\*(.*?)\*/gim, '<em>$1</em>');
    html = html.replace(/_(.*?)_/gim, '<em>$1</em>');

    // Code blocks
    html = html.replace(/```(.*?)```/gims, '<pre><code>$1</code></pre>');

    // Inline code
    html = html.replace(/`(.*?)`/gim, '<code>$1</code>');

    // Links
    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/gim, '<a href="$2" target="_blank">$1</a>');

    // Images
    html = html.replace(/!\[([^\]]*)\]\(([^)]+)\)/gim, '<img src="$2" alt="$1" />');

    // Unordered lists
    html = html.replace(/^\* (.*$)/gim, '<li>$1</li>');
    html = html.replace(/^- (.*$)/gim, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>)/gims, '<ul>$1</ul>');

    // Line breaks
    html = html.replace(/\n$/gim, '<br />');

    return html;
  };

  return (
    <div className={styles.tool}>
      <div className={styles.toolHeader}>
        <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
          ← Back
        </button>
        <div className={styles.toolTitle}>
          <span className={styles.toolIcon}>📝</span>
          Markdown Preview
        </div>
      </div>

      <div className={styles.toolContent}>
        <div className={styles.splitView}>
          <div className={styles.editorSection}>
            <label className={styles.label}>Markdown Input</label>
            <textarea
              className={styles.textarea}
              value={markdown}
              onChange={(e) => setMarkdown(e.target.value)}
              placeholder="# Hello World&#10;&#10;Write your **markdown** here...&#10;&#10;- List item 1&#10;- List item 2&#10;&#10;```javascript&#10;console.log('code block');&#10;```"
              rows={20}
            />
          </div>

          <div className={styles.previewSection}>
            <label className={styles.label}>Preview</label>
            <div 
              className={styles.markdownPreview}
              dangerouslySetInnerHTML={{ __html: renderMarkdown(markdown) }}
            />
          </div>
        </div>
      </div>
    </div>
  );
};

export default MarkdownPreview;
