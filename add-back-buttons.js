const fs = require('fs');
const path = require('path');

const toolsDir = path.join(__dirname, 'src', 'renderer', 'src', 'components', 'galaxymind');
const files = fs.readdirSync(toolsDir).filter((f) => f.endsWith('.tsx') && f !== 'ToolsGrid.tsx');

const backButtonJSX = `      <button className={styles.backButton} onClick={() => setActiveGalaxyTool(null)}>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M19 12H5M12 19l-7-7 7-7"/>
        </svg>
        Back to Tools
      </button>
      
`;

files.forEach((file) => {
  const filePath = path.join(toolsDir, file);
  let content = fs.readFileSync(filePath, 'utf8');

  if (content.includes('backButton') || content.includes('Back to Tools')) {
    console.log(`Skipping ${file} - already has back button`);
    return;
  }

  if (!content.includes("from '../../store/store'")) {
    content = content.replace(
      /^import { useState(.*?) } from 'react';/m,
      "import { useState$1 } from 'react';\nimport { useStore } from '../../store/store';"
    );
  }

  if (!content.includes('setActiveGalaxyTool')) {
    const funcMatch = content.match(/export default function (\w+)\(\) {/);
    if (funcMatch) {
      const afterFunc = funcMatch[0];
      content = content.replace(
        afterFunc,
        afterFunc + '\n  const { setActiveGalaxyTool } = useStore();'
      );
    }
  }

  content = content.replace(
    /(\s*)<div className={styles\.toolHeader}>/,
    `$1${backButtonJSX}$1<div className={styles.toolHeader}>`
  );

  fs.writeFileSync(filePath, content, 'utf8');
  console.log(`Updated ${file}`);
});

console.log(`\nProcessed ${files.length} tool files`);
