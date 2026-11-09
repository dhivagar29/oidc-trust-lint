import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { lintPaths } from '../src/index.js';
import { isUnpinnedSub, RULES, lintPolicyDoc } from '../src/rules.js';
import { extractPolicies } from '../src/parse.js';

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

  it('accepts case-insensitive condition keys and operators', () => {
    const { findings } = lintPaths([fx('good', 'case-insensitive-keys.json')]);
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

describe('Mafee review: Deny never counts as Allow sub', () => {
  it('Allow without sub + Deny with sub => OIDC_SUB_MISSING', () => {
    const { findings } = lintPaths([fx('bad', 'allow-no-sub-deny-with-sub.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_MISSING'));
    // Deny statement itself produces no findings
    assert.equal(findings.filter((f) => f.jsonPath.includes('Statement[1]')).length, 0);
  });
});

describe('Mafee review: ForAllValues / ForAnyValue', () => {
  it('ForAllValues on sub => OIDC_SUB_FORALLVALUES (critical)', () => {
    const { findings } = lintPaths([fx('bad', 'forallvalues-sub.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_FORALLVALUES'));
    const f = findings.find((x) => x.ruleId === 'OIDC_SUB_FORALLVALUES');
    assert.equal(f.severity, 'critical');
    assert.match(f.message, /absent/i);
    // Must not be miscounted as a real sub pin (still missing positive)
    // ForAllValues alone: we emit FORALLVALUES; also SUB_MISSING because no positive.
    assert.ok(ids(findings).includes('OIDC_SUB_MISSING'));
  });

  it('ForAnyValue: runs normal wildcard rules on values', () => {
    const { findings } = lintPaths([fx('bad', 'foranyvalue-wildcard-sub.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_WILDCARD_ORG'));
    assert.ok(!ids(findings).includes('OIDC_SUB_FORALLVALUES'));
    assert.ok(!ids(findings).includes('OIDC_SUB_MISSING'));
  });
});

describe('Mafee review: negatives alone are not a sub pin', () => {
  it('StringNotEquals-only sub => OIDC_SUB_MISSING', () => {
    const { findings } = lintPaths([fx('bad', 'stringnotequals-sub-only.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_MISSING'));
  });

  it('StringNotLike-only sub => OIDC_SUB_MISSING', () => {
    const { findings } = lintPaths([fx('bad', 'stringnotlike-sub-only.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_MISSING'));
  });
});

describe('Mafee review: wildcards', () => {
  it('repo:myorg* (wildcard before slash) => OIDC_SUB_WILDCARD_ANY', () => {
    const { findings } = lintPaths([fx('bad', 'wildcard-sub-org-prefix.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_WILDCARD_ANY'));
    assert.ok(!ids(findings).includes('OIDC_SUB_WILDCARD_ORG'));
  });

  it('checks every array element of sub values', () => {
    const { findings } = lintPaths([fx('bad', 'wildcard-sub-array-second.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_WILDCARD_ANY'));
  });

  it('treats ? as a wildcard like * (cross-org)', () => {
    const { findings } = lintPaths([fx('bad', 'wildcard-sub-question-org.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_WILDCARD_ANY'));
  });

  it('treats ? after slash as org-wide repo wildcard', () => {
    const { findings } = lintPaths([fx('bad', 'wildcard-sub-question.json')]);
    assert.ok(ids(findings).includes('OIDC_SUB_WILDCARD_ORG'));
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
      'OIDC_SUB_FORALLVALUES',
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

describe('in-memory Deny isolation', () => {
  it('lintPolicyDoc skips Deny even when it is GitHub OIDC', () => {
    const docs = extractPolicies({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Deny',
          Principal: {
            Federated: 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com',
          },
          Action: 'sts:AssumeRoleWithWebIdentity',
          Condition: {
            StringEquals: {
              'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
            },
          },
        },
      ],
    });
    const findings = lintPolicyDoc(docs[0]);
    assert.deepEqual(findings, []);
  });
});
