import React, { useState } from 'react';
import ToolWrapper from './ToolWrapper';
import styles from './SharedTool.module.css';
import { MarkdownIcon } from '../common/Icons';

const MarkdownPreview: React.FC = () => {
  const [markdown, setMarkdown] = useState('');

  const renderMarkdown = (text: string): string => {
    let html = text;

    html = html.replace(/^### (.*$)/gim, '<h3>$1</h3>');
    html = html.replace(/^## (.*$)/gim, '<h2>$1</h2>');
    html = html.replace(/^# (.*$)/gim, '<h1>$1</h1>');

    html = html.replace(/\*\*(.*?)\*\*/gim, '<strong>$1</strong>');
    html = html.replace(/__(.*?)__/gim, '<strong>$1</strong>');

    html = html.replace(/\*(.*?)\*/gim, '<em>$1</em>');
    html = html.replace(/_(.*?)_/gim, '<em>$1</em>');

    html = html.replace(/```(.*?)```/gims, '<pre><code>$1</code></pre>');

    html = html.replace(/`(.*?)`/gim, '<code>$1</code>');

    html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/gim, '<a href="$2" target="_blank">$1</a>');

    html = html.replace(/!\[([^\]]*)\]\(([^)]+)\)/gim, '<img src="$2" alt="$1" />');

    html = html.replace(/^\* (.*$)/gim, '<li>$1</li>');
    html = html.replace(/^- (.*$)/gim, '<li>$1</li>');
    html = html.replace(/(<li>.*<\/li>)/gims, '<ul>$1</ul>');

    html = html.replace(/\n$/gim, '<br />');

    return html;
  };

  return (
    <ToolWrapper
      title="Markdown Preview"
      icon={<MarkdownIcon />}
      description="Preview markdown syntax in real-time"
    >
      <div style={{ display: 'flex', gap: '20px', height: '100%' }}>
        <div style={{ flex: 1 }}>
          <label className={styles.label}>Markdown Input</label>
          <textarea
            className={styles.textarea}
            value={markdown}
            onChange={(e) => setMarkdown(e.target.value)}
            placeholder="# Hello World&#10;&#10;Write your **markdown** here...&#10;&#10;- List item 1&#10;- List item 2&#10;&#10;```javascript&#10;console.log('code block');&#10;```"
            rows={20}
            style={{ minHeight: '400px' }}
          />
        </div>

        <div style={{ flex: 1 }}>
          <label className={styles.label}>Preview</label>
          <div
            style={{
              background: 'var(--color-bg-tertiary)',
              border: '1px solid var(--color-border)',
              borderRadius: 'var(--border-radius-md)',
              padding: '12px 14px',
              minHeight: '400px',
              overflow: 'auto',
              color: 'var(--color-text-primary)',
              fontSize: '14px',
              lineHeight: '1.6',
            }}
            dangerouslySetInnerHTML={{ __html: renderMarkdown(markdown) }}
          />
        </div>
      </div>
    </ToolWrapper>
  );
};

export default MarkdownPreview;
