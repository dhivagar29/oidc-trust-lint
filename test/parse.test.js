import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { extractPolicies, isGitHubOidcStatement } from '../src/parse.js';

describe('extractPolicies', () => {
  it('accepts plain IAM trust policy', () => {
    const docs = extractPolicies({
      Version: '2012-10-17',
      Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRoleWithWebIdentity' }],
    });
    assert.equal(docs.length, 1);
    assert.equal(docs[0].source, 'iam-json');
    assert.equal(docs[0].policy.Statement.length, 1);
  });

  it('accepts a bare Statement object', () => {
    const docs = extractPolicies({
      Effect: 'Allow',
      Principal: { Federated: 'arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com' },
      Action: 'sts:AssumeRoleWithWebIdentity',
    });
    assert.equal(docs.length, 1);
  });

  it('parses terraform resource map', () => {
    const docs = extractPolicies({
      resource: {
        aws_iam_role: {
          x: {
            assume_role_policy: JSON.stringify({
              Version: '2012-10-17',
              Statement: [{ Effect: 'Allow', Action: 'sts:AssumeRoleWithWebIdentity' }],
            }),
          },
        },
      },
    });
    assert.equal(docs.length, 1);
    assert.equal(docs[0].source, 'terraform');
  });

  it('parses CloudFormation role', () => {
    const docs = extractPolicies({
      Resources: {
        R: {
          Type: 'AWS::IAM::Role',
          Properties: {
            AssumeRolePolicyDocument: {
              Version: '2012-10-17',
              Statement: [{ Effect: 'Allow' }],
            },
          },
        },
      },
    });
    assert.equal(docs.length, 1);
    assert.equal(docs[0].source, 'cloudformation');
  });
});

describe('isGitHubOidcStatement', () => {
  it('detects Federated principal', () => {
    assert.equal(
      isGitHubOidcStatement({
        Principal: {
          Federated: 'arn:aws:iam::1:oidc-provider/token.actions.githubusercontent.com',
        },
      }),
      true,
    );
  });

  it('detects condition key host', () => {
    assert.equal(
      isGitHubOidcStatement({
        Condition: {
          StringEquals: {
            'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com',
          },
        },
      }),
      true,
    );
  });

  it('rejects unrelated', () => {
    assert.equal(
      isGitHubOidcStatement({
        Principal: { Service: 'lambda.amazonaws.com' },
      }),
      false,
    );
  });
});
