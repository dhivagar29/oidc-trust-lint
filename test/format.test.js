import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { formatHuman, formatJson, formatSarif, sortFindings } from '../src/format.js';
import { shouldFail } from '../src/index.js';

const sample = [
  {
    ruleId: 'OIDC_SUB_MISSING',
    severity: 'critical',
    file: '/tmp/a.json',
    jsonPath: '$.Statement[0].Condition',
    message: 'missing sub',
    fix: 'add sub',
  },
  {
    ruleId: 'OIDC_SUB_UNPINNED',
    severity: 'low',
    file: '/tmp/b.json',
    jsonPath: '$.Statement[0].Condition.StringLike["token.actions.githubusercontent.com:sub"]',
    message: 'unpinned',
    fix: 'pin',
  },
];

describe('formatters', () => {
  it('formatHuman includes rule ids', () => {
    const text = formatHuman(sample, { cwd: '/tmp' });
    assert.match(text, /OIDC_SUB_MISSING/);
    assert.match(text, /OIDC_SUB_UNPINNED/);
    assert.match(text, /2 finding/);
  });

  it('formatHuman empty', () => {
    assert.equal(formatHuman([]), 'oidc-trust-lint: no findings\n');
  });

  it('formatJson structure', () => {
    const obj = JSON.parse(formatJson(sample, { filesScanned: 2, cwd: '/tmp' }));
    assert.equal(obj.tool, 'oidc-trust-lint');
    assert.equal(obj.findingCount, 2);
    assert.equal(obj.findings[0].file, 'a.json');
  });

  it('formatSarif structure', () => {
    const sarif = JSON.parse(formatSarif(sample, { cwd: '/tmp' }));
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].results.length, 2);
    assert.ok(sarif.runs[0].tool.driver.rules.length >= 9);
  });
});

describe('shouldFail / sort', () => {
  it('fail-on high catches critical', () => {
    assert.equal(shouldFail(sample, 'high'), true);
  });

  it('fail-on critical ignores low-only', () => {
    assert.equal(shouldFail([sample[1]], 'critical'), false);
  });

  it('fail-on none never fails', () => {
    assert.equal(shouldFail(sample, 'none'), false);
  });

  it('sortFindings orders by severity', () => {
    const sorted = sortFindings([sample[1], sample[0]]);
    assert.equal(sorted[0].severity, 'critical');
  });
});
