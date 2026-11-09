import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { lintPaths } from '../src/index.js';
import { isUnpinnedSub, RULES } from '../src/rules.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const fx = (...p) => path.join(__dirname, 'fixtures', ...p);

function ids(findings) {
  return findings.map((f) => f.ruleId).sort();
}

describe('good fixtures', () => {
  it('pinned branch has no findings', () => {
    const { findings } = lintPaths([fx('good', 'pinned-repo-branch.json')]);
    assert.deepEqual(findings, []);
  });

  it('pinned environment has no findings', () => {
    const { findings } = lintPaths([fx('good', 'pinned-environment.json')]);
    assert.deepEqual(findings, []);
  });

  it('job_workflow_ref has no findings', () => {
    const { findings } = lintPaths([fx('good', 'job-workflow-ref.json')]);
    assert.deepEqual(findings, []);
  });

  it('ignores non-GitHub OIDC trust policies', () => {
    const { findings } = lintPaths([fx('good', 'ec2-trust-ignored.json')]);
    assert.deepEqual(findings, []);
  });
});

describe('bad fixtures per rule', () => {
  it('OIDC_AUD_MISSING', () => {
    const { findings } = lintPaths([fx('bad', 'missing-aud.json')]);
    assert.ok(ids(findings).includes('OIDC_AUD_MISSING'));
  });

  it('OIDC_AUD_WRONG', () => {
    const { findings } = lintPaths([fx('bad', 'wrong-aud.json')]);
    assert.ok(ids(findings).includes('OIDC_AUD_WRONG'));
  });

  it('OIDC_SUB_MISSING', () => {
    const { findings } = lintPaths([fx('bad', 'missing-sub.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_MISSING'));
  });

  it('OIDC_SUB_WILDCARD_ANY', () => {
    const { findings } = lintPaths([fx('bad', 'wildcard-sub-any-repo.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_WILDCARD_ANY'));
  });

  it('OIDC_SUB_WILDCARD_ORG', () => {
    const { findings } = lintPaths([fx('bad', 'wildcard-sub-org.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_WILDCARD_ORG'));
  });

  it('OIDC_STRINGLIKE_UNNECESSARY', () => {
    const { findings } = lintPaths([fx('bad', 'stringlike-equals.json')]);
    assert.ok(ids(findings).includes('OIDC_STRINGLIKE_UNNECESSARY'));
  });

  it('OIDC_SUB_UNPINNED', () => {
    const { findings } = lintPaths([fx('bad', 'sub-unpinned.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_UNPINNED'));
  });

  it('OIDC_PRINCIPAL_WRONG for bare host', () => {
    const { findings } = lintPaths([fx('bad', 'wrong-principal.json')]);
    assert.ok(ids(findings).includes('OIDC_PRINCIPAL_WRONG'));
  });

  it('OIDC_PRINCIPAL_WRONG for Federated *', () => {
    const { findings } = lintPaths([fx('bad', 'wildcard-principal.json')]);
    assert.ok(ids(findings).includes('OIDC_PRINCIPAL_WRONG'));
  });

  it('OIDC_RISKY_PRINCIPALS', () => {
    const { findings } = lintPaths([fx('bad', 'risky-principals.json')]);
    assert.ok(ids(findings).includes('OIDC_RISKY_PRINCIPALS'));
  });
});

describe('terraform and cloudformation', () => {
  it('extracts terraform assume_role_policy string and flags repo:*', () => {
    const { findings } = lintPaths([fx('terraform', 'aws_iam_role.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_WILDCARD_ANY'));
  });

  it('extracts CloudFormation AssumeRolePolicyDocument and flags missing sub', () => {
    const { findings } = lintPaths([fx('cloudformation', 'iam_role.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_MISSING'));
  });
});

describe('isUnpinnedSub', () => {
  it('detects pins', () => {
    assert.equal(isUnpinnedSub('repo:acme/widgets:ref:refs/heads/main'), false);
    assert.equal(isUnpinnedSub('repo:acme/widgets:environment:prod'), false);
    assert.equal(isUnpinnedSub('repo:acme/widgets:ref:refs/tags/v1.0.0'), false);
  });

  it('detects unpinned', () => {
    assert.equal(isUnpinnedSub('repo:acme/widgets:*'), true);
    assert.equal(isUnpinnedSub('repo:acme/widgets'), true);
    assert.equal(isUnpinnedSub('repo:acme/widgets:ref:refs/heads/*'), true);
  });
});

describe('RULES catalog', () => {
  it('exports expected rule ids', () => {
    const expected = [
      'OIDC_AUD_MISSING',
      'OIDC_AUD_WRONG',
      'OIDC_SUB_MISSING',
      'OIDC_SUB_WILDCARD_ANY',
      'OIDC_SUB_WILDCARD_ORG',
      'OIDC_STRINGLIKE_UNNECESSARY',
      'OIDC_SUB_UNPINNED',
      'OIDC_PRINCIPAL_WRONG',
      'OIDC_RISKY_PRINCIPALS',
    ];
    assert.deepEqual(Object.keys(RULES).sort(), expected.sort());
  });
});
