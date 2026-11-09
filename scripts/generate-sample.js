#!/usr/bin/env node
/**
 * Produce docs/sample-output.txt and docs/sample.sarif from real fixtures.
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'src', 'cli.js');
const fixtures = path.join(root, 'test', 'fixtures');
const docs = path.join(root, 'docs');

fs.mkdirSync(docs, { recursive: true });

const text = spawnSync(
  process.execPath,
  [cli, fixtures, '--format', 'text', '--fail-on', 'none'],
  { encoding: 'utf8', cwd: root },
);
if (text.error) throw text.error;

const sarifPath = path.join(docs, 'sample.sarif');
const sarif = spawnSync(
  process.execPath,
  [cli, fixtures, '--format', 'sarif', '--fail-on', 'none', '--sarif', sarifPath],
  { encoding: 'utf8', cwd: root },
);
if (sarif.error) throw sarif.error;

fs.writeFileSync(path.join(docs, 'sample-output.txt'), text.stdout);
// sarif already written; also ensure stdout copy matches file
if (!fs.existsSync(sarifPath)) {
  fs.writeFileSync(sarifPath, sarif.stdout);
}

process.stdout.write(`Wrote docs/sample-output.txt (${text.stdout.length} bytes)\n`);
process.stdout.write(`Wrote docs/sample.sarif (${fs.statSync(sarifPath).size} bytes)\n`);
