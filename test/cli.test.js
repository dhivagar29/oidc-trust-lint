import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const cli = path.join(__dirname, '..', 'src', 'cli.js');
const fx = (...p) => path.join(__dirname, 'fixtures', ...p);

function run(args, opts = {}) {
  return spawnSync(process.execPath, [cli, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || path.join(__dirname, '..'),
  });
}

describe('CLI', () => {
  it('exits 0 on clean good fixture with --fail-on high', () => {
    const r = run([fx('good', 'pinned-repo-branch.json'), '--fail-on', 'high']);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /no findings/);
  });

  it('exits 1 on critical finding with default --fail-on high', () => {
    const r = run([fx('bad', 'missing-sub.json')]);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /OIDC_SUB_MISSING/);
  });

  it('writes json and sarif side outputs', () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'oidc-lint-'));
    const jsonOut = path.join(dir, 'out.json');
    const sarifOut = path.join(dir, 'out.sarif');
    const r = run([
      fx('bad', 'missing-aud.json'),
      '--fail-on', 'none',
      '--out', jsonOut,
      '--sarif', sarifOut,
      '--format', 'text',
    ]);
    assert.equal(r.status, 0, r.stderr);
    const j = JSON.parse(fs.readFileSync(jsonOut, 'utf8'));
    const s = JSON.parse(fs.readFileSync(sarifOut, 'utf8'));
    assert.ok(j.findingCount >= 1);
    assert.equal(s.version, '2.1.0');
  });

  it('--format json prints JSON', () => {
    const r = run([fx('good', 'pinned-repo-branch.json'), '--format', 'json', '--fail-on', 'none']);
    assert.equal(r.status, 0);
    const j = JSON.parse(r.stdout);
    assert.equal(j.findingCount, 0);
  });

  it('--help exits 0', () => {
    const r = run(['--help']);
    assert.equal(r.status, 0);
    assert.match(r.stdout, /Usage/);
  });
});
