/**
 * Discover candidate policy JSON files under a path.
 */
import fs from 'node:fs';
import path from 'node:path';

const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  '.terraform',
  'dist',
  'coverage',
  '.venv',
  'venv',
]);

/**
 * @param {string} root
 * @param {{ extensions?: string[] }} [opts]
 * @returns {string[]} absolute paths
 */
export function findPolicyFiles(root, opts = {}) {
  const extensions = new Set(
    (opts.extensions || ['.json']).map((e) => e.toLowerCase()),
  );
  const out = [];
  walk(path.resolve(root), extensions, out);
  return out.sort();
}

function walk(dir, extensions, out) {
  let entries;
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const ent of entries) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) {
      if (SKIP_DIRS.has(ent.name)) continue;
      if (ent.name.startsWith('.') && ent.name !== '.github') continue;
      walk(full, extensions, out);
    } else if (ent.isFile()) {
      const ext = path.extname(ent.name).toLowerCase();
      if (extensions.has(ext)) out.push(full);
    }
  }
}
