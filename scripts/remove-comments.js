const fs = require('fs');
const path = require('path');

const SRC_DIR = path.join(__dirname, '..', 'src');

function findTsFiles(dir) {
  const files = [];
  const entries = fs.readdirSync(dir, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...findTsFiles(fullPath));
    } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.tsx'))) {
      files.push(fullPath);
    }
  }

  return files;
}

function isLicenseHeader(content) {
  const firstLines = content.slice(0, 500);
  return /^\s*\/\*[\s\S]*?(copyright|license|MIT|Apache|GPL|ISC|BSD)/i.test(firstLines);
}

function removeComments(content, filePath) {
  const isTsx = filePath.endsWith('.tsx');
  const hasLicenseHeader = isLicenseHeader(content);

  let licenseHeaderEnd = 0;
  if (hasLicenseHeader) {
    const match = content.match(/^\s*\/\*[\s\S]*?\*\//);
    if (match) {
      licenseHeaderEnd = match[0].length;
    }
  }

  const header = content.slice(0, licenseHeaderEnd);
  let code = content.slice(licenseHeaderEnd);

  const result = [];
  let i = 0;

  while (i < code.length) {
    if (code[i] === '"' || code[i] === "'" || code[i] === '`') {
      const quote = code[i];
      result.push(quote);
      i++;

      while (i < code.length) {
        if (code[i] === '\\' && i + 1 < code.length) {
          result.push(code[i], code[i + 1]);
          i += 2;
          continue;
        }
        if (code[i] === quote) {
          result.push(quote);
          i++;
          break;
        }
        result.push(code[i]);
        i++;
      }
      continue;
    }

    if (isTsx && code.slice(i, i + 2) === '{/*') {
      result.push('{/*');
      i += 3;
      let depth = 1;
      while (i < code.length && depth > 0) {
        if (code.slice(i, i + 2) === '*/') {
          depth--;
          result.push('*/');
          i += 2;
          if (code[i] === '}') {
            result.push('}');
            i++;
            break;
          }
          continue;
        }
        if (code.slice(i, i + 2) === '/*') {
          depth++;
          result.push('/*');
          i += 2;
          continue;
        }
        result.push(code[i]);
        i++;
      }
      continue;
    }

    if (code.slice(i, i + 2) === '//') {
      if (
        code.slice(i - 5, i) === 'http:' ||
        code.slice(i - 6, i) === 'https:' ||
        code.slice(i - 5, i) === 'ftp:' ||
        code.slice(i - 5, i) === 'ws:' ||
        code.slice(i - 6, i) === 'wss:'
      ) {
        result.push('//');
        i += 2;
        continue;
      }

      while (i < code.length && code[i] !== '\n') {
        i++;
      }
      continue;
    }

    if (code.slice(i, i + 2) === '/*') {
      i += 2;
      while (i < code.length && code.slice(i, i + 2) !== '*/') {
        i++;
      }
      if (i < code.length) {
        i += 2;
      }
      continue;
    }

    result.push(code[i]);
    i++;
  }

  return header + result.join('');
}

function processFiles() {
  const files = findTsFiles(SRC_DIR);
  let processedCount = 0;

  for (const file of files) {
    const content = fs.readFileSync(file, 'utf-8');
    const cleaned = removeComments(content, file);

    if (content !== cleaned) {
      fs.writeFileSync(file, cleaned, 'utf-8');
      console.log(`Processed: ${path.relative(SRC_DIR, file)}`);
    } else {
      console.log(`No changes: ${path.relative(SRC_DIR, file)}`);
    }
    processedCount++;
  }

  return processedCount;
}

const count = processFiles();
console.log(`\nTotal files processed: ${count}`);
