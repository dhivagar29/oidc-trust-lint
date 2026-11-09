/**
 * OIDC trust-policy lint rules for GitHub Actions → AWS IAM roles.
 */
import {
  GITHUB_OIDC_HOST,
  EXPECTED_AUD,
  isGitHubOidcStatement,
  flattenValues,
  flattenActions,
  listConditions,
  oidcClaimKey,
  isPositiveStringOp,
  isNegativeStringOp,
} from './parse.js';

/** @typedef {'critical'|'high'|'medium'|'low'|'info'} Severity */

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

export const RULES = {
  OIDC_AUD_MISSING: {
    id: 'OIDC_AUD_MISSING',
    severity: 'critical',
    title: 'Missing audience (aud) condition',
  },
  OIDC_AUD_WRONG: {
    id: 'OIDC_AUD_WRONG',
    severity: 'critical',
    title: 'Audience (aud) is not sts.amazonaws.com',
  },
  OIDC_SUB_MISSING: {
    id: 'OIDC_SUB_MISSING',
    severity: 'critical',
    title: 'Missing subject (sub) condition',
  },
  OIDC_SUB_FORALLVALUES: {
    id: 'OIDC_SUB_FORALLVALUES',
    severity: 'critical',
    title: 'ForAllValues quantifier on sub is not a real restriction',
  },
  OIDC_SUB_WILDCARD_ANY: {
    id: 'OIDC_SUB_WILDCARD_ANY',
    severity: 'critical',
    title: 'Subject wildcard allows any GitHub org/repo (or spans orgs)',
  },
  OIDC_SUB_WILDCARD_ORG: {
    id: 'OIDC_SUB_WILDCARD_ORG',
    severity: 'high',
    title: 'Subject wildcard allows any repo in an org',
  },
  OIDC_STRINGLIKE_UNNECESSARY: {
    id: 'OIDC_STRINGLIKE_UNNECESSARY',
    severity: 'medium',
    title: 'StringLike used where StringEquals suffices',
  },
  OIDC_SUB_UNPINNED: {
    id: 'OIDC_SUB_UNPINNED',
    severity: 'low',
    title: 'Subject not pinned to a branch, tag, or environment',
  },
  OIDC_SUB_LITERAL_WILDCARD: {
    id: 'OIDC_SUB_LITERAL_WILDCARD',
    severity: 'low',
    title: 'Exact-match operator treats * / ? as literal characters',
  },
  OIDC_PRINCIPAL_WRONG: {
    id: 'OIDC_PRINCIPAL_WRONG',
    severity: 'critical',
    title: 'Wrong or wildcard Federated principal for GitHub OIDC',
  },
  OIDC_RISKY_PRINCIPALS: {
    id: 'OIDC_RISKY_PRINCIPALS',
    severity: 'high',
    title: 'AssumeRoleWithWebIdentity combined with other risky principals',
  },
};

/**
 * @typedef {{
 *   ruleId: string,
 *   severity: Severity,
 *   file: string,
 *   jsonPath: string,
 *   message: string,
 *   fix: string,
 * }} Finding
 */

/**
 * Lint one normalized policy document.
 * Deny statements are skipped entirely — a Deny never counts as the Allow's restriction.
 * @param {{ file: string, pathPrefix: string, policy: object }} doc
 * @returns {Finding[]}
 */
export function lintPolicyDoc(doc) {
  const findings = [];
  const statements = doc.policy.Statement || [];
  statements.forEach((stmt, idx) => {
    const stmtPath = `${doc.pathPrefix}.Statement[${idx}]`;
    if (!isGitHubOidcStatement(stmt)) return;
    // Deny is never evaluated; its conditions do not satisfy a sibling Allow.
    if (String(stmt.Effect || 'Allow').toLowerCase() !== 'allow') return;

    findings.push(...checkPrincipal(doc, stmt, stmtPath));
    findings.push(...checkRiskyPrincipals(doc, stmt, stmtPath));
    findings.push(...checkAud(doc, stmt, stmtPath));
    findings.push(...checkSub(doc, stmt, stmtPath));
    findings.push(...checkStringLike(doc, stmt, stmtPath));
  });
  return findings;
}

function checkPrincipal(doc, stmt, stmtPath) {
  const findings = [];
  const federated = flattenValues(stmt.Principal?.Federated);
  const path = `${stmtPath}.Principal.Federated`;

  if (federated.length === 0) {
    findings.push(finding(RULES.OIDC_PRINCIPAL_WRONG, doc, path,
      'GitHub OIDC condition keys are present but Principal.Federated is missing.',
      `Set Principal.Federated to "arn:aws:iam::<account-id>:oidc-provider/${GITHUB_OIDC_HOST}".`,
    ));
    return findings;
  }

  for (const value of federated) {
    const v = String(value);
    if (v === '*' || /[*?]/.test(v)) {
      findings.push(finding(RULES.OIDC_PRINCIPAL_WRONG, doc, path,
        `Federated principal contains a wildcard: "${v}".`,
        `Pin Principal.Federated to the account OIDC provider ARN for ${GITHUB_OIDC_HOST}.`,
      ));
      continue;
    }
    if (!v.toLowerCase().includes(GITHUB_OIDC_HOST.toLowerCase())) {
      findings.push(finding(RULES.OIDC_PRINCIPAL_WRONG, doc, path,
        `Federated principal does not reference ${GITHUB_OIDC_HOST}: "${v}".`,
        `Use arn:aws:iam::<account-id>:oidc-provider/${GITHUB_OIDC_HOST}.`,
      ));
      continue;
    }
    if (!/^arn:aws(-[a-z]+)?:iam::\d{12}:oidc-provider\/token\.actions\.githubusercontent\.com$/i.test(v)) {
      findings.push(finding(RULES.OIDC_PRINCIPAL_WRONG, doc, path,
        `Federated principal is not a well-formed IAM OIDC provider ARN: "${v}".`,
        `Expected arn:aws:iam::<12-digit-account>:oidc-provider/${GITHUB_OIDC_HOST}.`,
      ));
    }
  }
  return findings;
}

function checkRiskyPrincipals(doc, stmt, stmtPath) {
  const findings = [];
  const actions = flattenActions(stmt.Action);
  const assumesWebId = actions.some(
    (a) => a === 'sts:AssumeRoleWithWebIdentity' || a === 'sts:*' || a === '*',
  );
  if (!assumesWebId) return findings;

  const principal = stmt.Principal;
  if (!principal || typeof principal !== 'object') return findings;

  const risky = [];
  for (const [kind, raw] of Object.entries(principal)) {
    if (kind === 'Federated' || kind === 'federated') continue;
    const values = flattenValues(raw).map(String);
    for (const v of values) {
      if (v === '*' || kind === 'AWS' || kind === 'Service' || kind === 'CanonicalUser') {
        risky.push(`${kind}=${v}`);
      }
    }
  }

  const fed = flattenValues(principal.Federated).map(String);
  if (fed.some((v) => v === '*' || /[*?]/.test(v))) {
    risky.push('Federated=*');
  }

  if (risky.length) {
    findings.push(finding(RULES.OIDC_RISKY_PRINCIPALS, doc, `${stmtPath}.Principal`,
      `sts:AssumeRoleWithWebIdentity is Allow alongside other principals: ${risky.join(', ')}.`,
      'Keep GitHub OIDC assume statements limited to Principal.Federated for the GitHub OIDC provider. Split unrelated trust into separate statements or roles.',
    ));
  }
  return findings;
}

function checkAud(doc, stmt, stmtPath) {
  const findings = [];
  const conditions = listConditions(stmt, stmtPath);
  const audKey = oidcClaimKey('aud');
  // Positive aud conditions only (Ignore ForAllValues — treat separately if needed)
  const audEntries = conditions.filter(
    (c) => c.claim === 'aud' && c.isOidc && isPositiveStringOp(c.operator) && c.quantifier !== 'ForAllValues',
  );

  if (audEntries.length === 0) {
    // Also accept ForAnyValue as positive (quantifier stripped already for matching)
    const anyAud = conditions.filter(
      (c) => c.claim === 'aud' && c.isOidc && isPositiveStringOp(c.operator) && c.quantifier === 'ForAnyValue',
    );
    if (anyAud.length === 0) {
      findings.push(finding(RULES.OIDC_AUD_MISSING, doc, `${stmtPath}.Condition`,
        `No "${audKey}" condition. Tokens with any audience may be accepted.`,
        `Add StringEquals "${audKey}": "${EXPECTED_AUD}".`,
      ));
      return findings;
    }
    for (const entry of anyAud) {
      const ok = entry.values.some((v) => v === EXPECTED_AUD);
      if (!ok) {
        findings.push(finding(RULES.OIDC_AUD_WRONG, doc, entry.jsonPath,
          `Audience values [${entry.values.map((v) => JSON.stringify(v)).join(', ')}] do not include "${EXPECTED_AUD}".`,
          `Set "${audKey}" to "${EXPECTED_AUD}" (StringEquals).`,
        ));
      }
    }
    return findings;
  }

  for (const entry of audEntries) {
    const ok = entry.values.some((v) => v === EXPECTED_AUD);
    if (!ok) {
      findings.push(finding(RULES.OIDC_AUD_WRONG, doc, entry.jsonPath,
        `Audience values [${entry.values.map((v) => JSON.stringify(v)).join(', ')}] do not include "${EXPECTED_AUD}".`,
        `Set "${audKey}" to "${EXPECTED_AUD}" (StringEquals).`,
      ));
    }
  }
  return findings;
}

function checkSub(doc, stmt, stmtPath) {
  const findings = [];
  const conditions = listConditions(stmt, stmtPath);
  const subKey = oidcClaimKey('sub');
  const subEntries = conditions.filter((c) => c.claim === 'sub' && c.isOidc);

  if (subEntries.length === 0) {
    findings.push(finding(RULES.OIDC_SUB_MISSING, doc, `${stmtPath}.Condition`,
      `No "${subKey}" condition. Any GitHub repository that can obtain an OIDC token may assume this role.`,
      `Add a StringLike/StringEquals condition on "${subKey}" pinned to repo:<org>/<repo>:...`,
    ));
    return findings;
  }

  // ForAllValues on sub is never a real restriction for single-valued claims.
  const forAll = subEntries.filter((c) => c.quantifier === 'ForAllValues');
  for (const entry of forAll) {
    findings.push(finding(RULES.OIDC_SUB_FORALLVALUES, doc, entry.jsonPath,
      `ForAllValues on "${entry.key}" does not restrict a single-valued claim: the condition is true when the key is absent from the request context. Treat this as no sub restriction.`,
      `Use StringEquals or StringLike (optionally ForAnyValue:) on "${subKey}" without ForAllValues.`,
    ));
  }

  // Positive sub restrictions: StringEquals / StringLike, with null or ForAnyValue quantifier.
  const positive = subEntries.filter(
    (c) => isPositiveStringOp(c.operator) && c.quantifier !== 'ForAllValues',
  );

  if (positive.length === 0) {
    // Only negatives and/or ForAllValues → no positive sub restriction
    const onlyNegatives = subEntries.every(
      (c) => isNegativeStringOp(c.operator) || c.quantifier === 'ForAllValues',
    );
    if (onlyNegatives) {
      findings.push(finding(RULES.OIDC_SUB_MISSING, doc, `${stmtPath}.Condition`,
        `No positive StringEquals/StringLike "${subKey}" condition (only StringNot*/ForAllValues). Negations alone do not pin which repos may assume.`,
        `Add a StringEquals or StringLike condition on "${subKey}" pinned to repo:<org>/<repo>:...`,
      ));
    }
    return findings;
  }

  // Run wildcard / unpinned rules on every value of every positive entry
  // (ForAnyValue is treated as the plain operator).
  for (const entry of positive) {
    for (const value of entry.values) {
      findings.push(...classifySub(doc, entry, value));
    }
  }
  return findings;
}

function hasWildcardChar(v) {
  return /[*?]/.test(v);
}

/** StringEquals / StringEqualsIgnoreCase treat * and ? as literals (incl. ForAnyValue:). */
function isExactMatchOp(operator) {
  const n = String(operator).replace(/\s+/g, '').toLowerCase();
  return n === 'stringequals' || n === 'stringequalsignorecase';
}

/**
 * Classify one sub value. Every array element is checked independently.
 * Under exact-match operators, * / ? are literals → OIDC_SUB_LITERAL_WILDCARD (not WILDCARD_*).
 */
function classifySub(doc, entry, value) {
  const findings = [];
  const v = String(value);
  const exact = isExactMatchOp(entry.operator);

  // Exact-match + * or ? → role is effectively unassumable (literals), not a broad grant.
  if (exact && hasWildcardChar(v)) {
    findings.push(finding(RULES.OIDC_SUB_LITERAL_WILDCARD, doc, entry.jsonPath,
      `Subject "${v}" uses ${entry.operator}, which treats "*" and "?" as literal characters. No GitHub OIDC token will match, so this role cannot be assumed.`,
      'Use StringLike with a pinned repo (and ref/environment), e.g. StringLike "token.actions.githubusercontent.com:sub": "repo:<org>/<repo>:ref:refs/heads/<branch>" — or drop the * / ? and use StringEquals for an exact sub.',
    ));
    return findings;
  }

  // Pattern operators (StringLike): real wildcards
  // Bare * or repo:* / repo:*:... → any org/repo
  if (
    v === '*' ||
    v === 'repo:*' ||
    /^repo:\*[/:?]/.test(v) ||
    /^repo:\*$/.test(v) ||
    v === 'repo:*:*'
  ) {
    findings.push(finding(RULES.OIDC_SUB_WILDCARD_ANY, doc, entry.jsonPath,
      `Subject "${v}" allows any organization/repository on GitHub.`,
      'Pin sub to repo:<org>/<repo>:ref:refs/heads/<branch> (or environment:/job_workflow_ref:).',
    ));
    return findings;
  }

  // Cross-org: wildcard in the org segment (before the first '/'), e.g. repo:myorg*
  const crossOrg = v.match(/^repo:([^/]*[*?][^/]*)(\/.*)?$/i);
  if (crossOrg) {
    findings.push(finding(RULES.OIDC_SUB_WILDCARD_ANY, doc, entry.jsonPath,
      `Subject "${v}" has a wildcard in the org segment ("${crossOrg[1]}"), so it can span other organizations (e.g. myorg* matches myorg-evil/...).`,
      'Pin the organization name with no * or ?: repo:<exact-org>/<repo>:...',
    ));
    return findings;
  }

  // repo:org/* → any repo in a fixed org
  const orgWild = v.match(/^repo:([^:/?*]+)\/[*?](.*)$/);
  if (orgWild) {
    findings.push(finding(RULES.OIDC_SUB_WILDCARD_ORG, doc, entry.jsonPath,
      `Subject "${v}" allows any repository under org "${orgWild[1]}".`,
      `Pin to a single repository, e.g. repo:${orgWild[1]}/<repo>:ref:refs/heads/main.`,
    ));
    return findings;
  }

  if (isUnpinnedSub(v)) {
    findings.push(finding(RULES.OIDC_SUB_UNPINNED, doc, entry.jsonPath,
      `Subject "${v}" is not pinned to a specific branch, tag, or environment.`,
      'Prefer repo:<org>/<repo>:ref:refs/heads/<branch>, :environment:<name>, or :job_workflow_ref:<org>/<repo>/.github/workflows/<file>@refs/heads/<branch>.',
    ));
  }

  return findings;
}

/**
 * A sub is "pinned" if it names a concrete ref, environment, or job_workflow_ref
 * without a wildcard that matches all refs.
 */
export function isUnpinnedSub(value) {
  const v = String(value);

  if (hasWildcardChar(v)) {
    // Exact-looking pins must not contain wildcards
    return true;
  }

  if (/^repo:[^:/]+\/[^:/]+:environment:.+$/.test(v)) return false;
  if (/^repo:[^:/]+\/[^:/]+:job_workflow_ref:.+$/.test(v)) return false;
  if (/^repo:[^:/]+\/[^:/]+:ref:refs\/(heads|tags)\/.+$/.test(v)) return false;

  return true;
}

function checkStringLike(doc, stmt, stmtPath) {
  const findings = [];
  const conditions = listConditions(stmt, stmtPath);
  for (const entry of conditions) {
    if (!/^StringLike$/i.test(entry.operator)) continue;
    if (entry.quantifier === 'ForAllValues') continue;
    if (!entry.isOidc) continue;
    const needsLike = entry.values.some((v) => /[*?]/.test(v));
    if (!needsLike) {
      findings.push(finding(RULES.OIDC_STRINGLIKE_UNNECESSARY, doc, entry.jsonPath,
        `StringLike used for "${entry.key}" but value(s) contain no wildcards: ${entry.values.map((v) => JSON.stringify(v)).join(', ')}.`,
        'Use StringEquals for exact matches. Reserve StringLike for patterns that include * or ?.',
      ));
    }
  }
  return findings;
}

function finding(rule, doc, jsonPath, message, fix) {
  return {
    ruleId: rule.id,
    severity: rule.severity,
    file: doc.file,
    jsonPath,
    message,
    fix,
  };
}

/**
 * @param {Severity} threshold
 * @param {Severity} severity
 */
export function severityAtOrAbove(threshold, severity) {
  const t = SEVERITY_ORDER.indexOf(threshold);
  const s = SEVERITY_ORDER.indexOf(severity);
  if (t < 0 || s < 0) return false;
  return s <= t;
}
