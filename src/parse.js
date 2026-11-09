/**
 * Load and normalize IAM trust / assume-role policy documents from JSON files.
 * Supports:
 *   - Plain IAM trust policy ({ Version, Statement })
 *   - Single Statement object / Statement array
 *   - Terraform JSON with aws_iam_role.*.assume_role_policy (stringified JSON)
 *   - CloudFormation AWS::IAM::Role AssumeRolePolicyDocument
 *
 * No network. No AWS credentials.
 */
import fs from 'node:fs';
import path from 'node:path';

export const GITHUB_OIDC_HOST = 'token.actions.githubusercontent.com';
export const EXPECTED_AUD = 'sts.amazonaws.com';

/**
 * @typedef {{ file: string, source: string, pathPrefix: string, policy: object }} PolicyDoc
 */

/**
 * @param {string} filePath
 * @returns {PolicyDoc[]}
 */
export function loadPolicyDocs(filePath) {
  const abs = path.resolve(filePath);
  const raw = fs.readFileSync(abs, 'utf8');
  let data;
  try {
    data = JSON.parse(raw);
  } catch (err) {
    throw new Error(`Invalid JSON in ${abs}: ${err.message}`);
  }
  return extractPolicies(data, abs);
}

/**
 * @param {unknown} data
 * @param {string} file
 * @returns {PolicyDoc[]}
 */
export function extractPolicies(data, file = '<memory>') {
  const docs = [];

  if (isTrustPolicyShape(data)) {
    docs.push({
      file,
      source: 'iam-json',
      pathPrefix: '$',
      policy: normalizePolicy(data),
    });
    return docs;
  }

  if (Array.isArray(data) && data.every(isStatementShape)) {
    docs.push({
      file,
      source: 'iam-json',
      pathPrefix: '$',
      policy: normalizePolicy({ Version: '2012-10-17', Statement: data }),
    });
    return docs;
  }

  if (isStatementShape(data)) {
    docs.push({
      file,
      source: 'iam-json',
      pathPrefix: '$',
      policy: normalizePolicy({ Version: '2012-10-17', Statement: [data] }),
    });
    return docs;
  }

  // Terraform JSON (resource map or full config)
  collectTerraform(data, file, '$', docs);

  // CloudFormation template
  collectCloudFormation(data, file, '$', docs);

  return docs;
}

function isTrustPolicyShape(data) {
  return (
    data &&
    typeof data === 'object' &&
    !Array.isArray(data) &&
    (Object.prototype.hasOwnProperty.call(data, 'Statement') ||
      Object.prototype.hasOwnProperty.call(data, 'statement'))
  );
}

function isStatementShape(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return false;
  const effect = data.Effect ?? data.effect;
  const action = data.Action ?? data.action;
  const principal = data.Principal ?? data.principal;
  return effect != null || action != null || principal != null;
}

function normalizePolicy(policy) {
  const statement = policy.Statement ?? policy.statement ?? [];
  const list = Array.isArray(statement) ? statement : [statement];
  return {
    Version: policy.Version ?? policy.version ?? '2012-10-17',
    Statement: list.map(normalizeStatement),
  };
}

function normalizeStatement(stmt) {
  return {
    Sid: stmt.Sid ?? stmt.sid,
    Effect: stmt.Effect ?? stmt.effect ?? 'Allow',
    Principal: stmt.Principal ?? stmt.principal,
    Action: stmt.Action ?? stmt.action,
    Condition: stmt.Condition ?? stmt.condition,
    NotPrincipal: stmt.NotPrincipal ?? stmt.notPrincipal,
  };
}

function collectTerraform(data, file, prefix, docs) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return;

  // resource.aws_iam_role.<name>
  const resource = data.resource;
  if (resource && typeof resource === 'object') {
    const roles = resource.aws_iam_role;
    if (roles && typeof roles === 'object') {
      for (const [name, cfg] of Object.entries(roles)) {
        const bodies = Array.isArray(cfg) ? cfg : [cfg];
        bodies.forEach((body, idx) => {
          const assume = body?.assume_role_policy;
          if (typeof assume === 'string') {
            pushParsedString(
              assume,
              file,
              `${prefix}.resource.aws_iam_role.${name}${Array.isArray(cfg) ? `[${idx}]` : ''}.assume_role_policy`,
              'terraform',
              docs,
            );
          } else if (assume && typeof assume === 'object') {
            docs.push({
              file,
              source: 'terraform',
              pathPrefix: `${prefix}.resource.aws_iam_role.${name}.assume_role_policy`,
              policy: normalizePolicy(assume),
            });
          }
        });
      }
    }
  }

  // Top-level aws_iam_role (flattened export)
  if (data.aws_iam_role && typeof data.aws_iam_role === 'object') {
    for (const [name, cfg] of Object.entries(data.aws_iam_role)) {
      const bodies = Array.isArray(cfg) ? cfg : [cfg];
      bodies.forEach((body, idx) => {
        const assume = body?.assume_role_policy;
        if (typeof assume === 'string') {
          pushParsedString(
            assume,
            file,
            `${prefix}.aws_iam_role.${name}${Array.isArray(cfg) ? `[${idx}]` : ''}.assume_role_policy`,
            'terraform',
            docs,
          );
        }
      });
    }
  }
}

function collectCloudFormation(data, file, prefix, docs) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) return;
  const resources = data.Resources ?? data.resources;
  if (!resources || typeof resources !== 'object') return;

  for (const [logicalId, res] of Object.entries(resources)) {
    const type = res?.Type ?? res?.type;
    if (type !== 'AWS::IAM::Role') continue;
    const props = res.Properties ?? res.properties ?? {};
    const doc = props.AssumeRolePolicyDocument ?? props.assumeRolePolicyDocument;
    if (!doc) continue;
    if (typeof doc === 'string') {
      pushParsedString(
        doc,
        file,
        `${prefix}.Resources.${logicalId}.Properties.AssumeRolePolicyDocument`,
        'cloudformation',
        docs,
      );
    } else if (typeof doc === 'object') {
      docs.push({
        file,
        source: 'cloudformation',
        pathPrefix: `${prefix}.Resources.${logicalId}.Properties.AssumeRolePolicyDocument`,
        policy: normalizePolicy(doc),
      });
    }
  }
}

function pushParsedString(str, file, pathPrefix, source, docs) {
  try {
    const parsed = JSON.parse(str);
    if (isTrustPolicyShape(parsed) || isStatementShape(parsed) || Array.isArray(parsed)) {
      const policy = isTrustPolicyShape(parsed)
        ? normalizePolicy(parsed)
        : Array.isArray(parsed)
          ? normalizePolicy({ Version: '2012-10-17', Statement: parsed })
          : normalizePolicy({ Version: '2012-10-17', Statement: [parsed] });
      docs.push({ file, source, pathPrefix, policy });
    }
  } catch {
    // leave unparseable embedded strings alone
  }
}

/**
 * True if a statement targets GitHub Actions OIDC
 * (Federated principal mentions token.actions.githubusercontent.com,
 *  or Condition keys use that host).
 */
export function isGitHubOidcStatement(stmt) {
  const federated = flattenValues(stmt?.Principal?.Federated ?? stmt?.Principal?.federated);
  if (federated.some((v) => String(v).includes(GITHUB_OIDC_HOST))) return true;

  const cond = stmt?.Condition;
  if (!cond || typeof cond !== 'object') return false;
  for (const op of Object.values(cond)) {
    if (!op || typeof op !== 'object') continue;
    for (const key of Object.keys(op)) {
      if (key.includes(GITHUB_OIDC_HOST)) return true;
    }
  }
  return false;
}

export function flattenValues(v) {
  if (v == null) return [];
  return Array.isArray(v) ? v : [v];
}

export function flattenActions(action) {
  return flattenValues(action).map(String);
}

/**
 * Collect Condition key/value pairs across operators.
 * @returns {{ operator: string, key: string, values: string[], jsonPath: string }[]}
 */
export function listConditions(stmt, stmtPath) {
  const cond = stmt?.Condition;
  if (!cond || typeof cond !== 'object') return [];
  const out = [];
  for (const [operator, map] of Object.entries(cond)) {
    if (!map || typeof map !== 'object') continue;
    for (const [key, raw] of Object.entries(map)) {
      out.push({
        operator,
        key,
        values: flattenValues(raw).map(String),
        jsonPath: `${stmtPath}.Condition.${operator}["${key}"]`,
      });
    }
  }
  return out;
}

export function oidcClaimKey(claim) {
  return `${GITHUB_OIDC_HOST}:${claim}`;
}
