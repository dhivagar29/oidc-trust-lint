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
  OIDC_SUB_WILDCARD_ANY: {
    id: 'OIDC_SUB_WILDCARD_ANY',
    severity: 'critical',
    title: 'Subject wildcard allows any GitHub org/repo',
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
 * @param {{ file: string, pathPrefix: string, policy: object }} doc
 * @returns {Finding[]}
 */
export function lintPolicyDoc(doc) {
  const findings = [];
  const statements = doc.policy.Statement || [];
  statements.forEach((stmt, idx) => {
    const stmtPath = `${doc.pathPrefix}.Statement[${idx}]`;
    if (!isGitHubOidcStatement(stmt)) return;
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
    // Condition keys reference GitHub OIDC but Federated principal missing/wrong shape
    findings.push(finding(RULES.OIDC_PRINCIPAL_WRONG, doc, path,
      'GitHub OIDC condition keys are present but Principal.Federated is missing.',
      `Set Principal.Federated to "arn:aws:iam::<account-id>:oidc-provider/${GITHUB_OIDC_HOST}".`,
    ));
    return findings;
  }

  for (const value of federated) {
    const v = String(value);
    if (v === '*' || v.includes('*')) {
      findings.push(finding(RULES.OIDC_PRINCIPAL_WRONG, doc, path,
        `Federated principal contains a wildcard: "${v}".`,
        `Pin Principal.Federated to the account OIDC provider ARN for ${GITHUB_OIDC_HOST}.`,
      ));
      continue;
    }
    if (!v.includes(GITHUB_OIDC_HOST)) {
      findings.push(finding(RULES.OIDC_PRINCIPAL_WRONG, doc, path,
        `Federated principal does not reference ${GITHUB_OIDC_HOST}: "${v}".`,
        `Use arn:aws:iam::<account-id>:oidc-provider/${GITHUB_OIDC_HOST}.`,
      ));
      continue;
    }
    // Must look like an IAM OIDC provider ARN, not a bare hostname
    if (!/^arn:aws:iam::\d{12}:oidc-provider\/token\.actions\.githubusercontent\.com$/.test(v)) {
      // Allow gov/china partitions lightly
      if (!/^arn:aws(-[a-z]+)?:iam::\d{12}:oidc-provider\/token\.actions\.githubusercontent\.com$/.test(v)) {
        findings.push(finding(RULES.OIDC_PRINCIPAL_WRONG, doc, path,
          `Federated principal is not a well-formed IAM OIDC provider ARN: "${v}".`,
          `Expected arn:aws:iam::<12-digit-account>:oidc-provider/${GITHUB_OIDC_HOST}.`,
        ));
      }
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

  // Also flag Federated=* already covered by PRINCIPAL_WRONG; still note combo
  const fed = flattenValues(principal.Federated).map(String);
  if (fed.some((v) => v === '*' || v.includes('*'))) {
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
  const audEntries = conditions.filter((c) => c.key === audKey || c.key.endsWith(':aud'));

  if (audEntries.length === 0) {
    findings.push(finding(RULES.OIDC_AUD_MISSING, doc, `${stmtPath}.Condition`,
      `No "${audKey}" condition. Tokens with any audience may be accepted.`,
      `Add StringEquals "${audKey}": "${EXPECTED_AUD}".`,
    ));
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
  const subEntries = conditions.filter((c) => c.key === subKey || c.key.endsWith(':sub'));

  if (subEntries.length === 0) {
    findings.push(finding(RULES.OIDC_SUB_MISSING, doc, `${stmtPath}.Condition`,
      `No "${subKey}" condition. Any GitHub repository that can obtain an OIDC token may assume this role.`,
      `Add a StringLike/StringEquals condition on "${subKey}" pinned to repo:<org>/<repo>:...`,
    ));
    return findings;
  }

  for (const entry of subEntries) {
    for (const value of entry.values) {
      findings.push(...classifySub(doc, entry, value));
    }
  }
  return findings;
}

function classifySub(doc, entry, value) {
  const findings = [];
  const v = String(value);

  // repo:* or * → any org/repo
  if (
    v === '*' ||
    v === 'repo:*' ||
    /^repo:\*:/.test(v) ||
    v === 'repo:*:*'
  ) {
    findings.push(finding(RULES.OIDC_SUB_WILDCARD_ANY, doc, entry.jsonPath,
      `Subject "${v}" allows any organization/repository on GitHub.`,
      'Pin sub to repo:<org>/<repo>:ref:refs/heads/<branch> (or environment:/job_workflow_ref:).',
    ));
    return findings;
  }

  // repo:org/* or repo:org/*:* → any repo in org
  const orgWild = v.match(/^repo:([^:/]+)\/\*($|:.*)/);
  if (orgWild) {
    findings.push(finding(RULES.OIDC_SUB_WILDCARD_ORG, doc, entry.jsonPath,
      `Subject "${v}" allows any repository under org "${orgWild[1]}".`,
      `Pin to a single repository, e.g. repo:${orgWild[1]}/<repo>:ref:refs/heads/main.`,
    ));
    return findings;
  }

  // Unpinned: repo:org/repo or repo:org/repo:* or repo:org/repo:ref:refs/heads/* etc.
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
 * without a trailing path wildcard that matches all refs.
 */
export function isUnpinnedSub(value) {
  const v = String(value);

  // Exact environment pin
  if (/^repo:[^:/]+\/[^:/]+:environment:[^*]+$/.test(v) && !v.includes('*')) {
    return false;
  }
  // Exact job_workflow_ref pin (may include @ref)
  if (/^repo:[^:/]+\/[^:/]+:job_workflow_ref:[^*]+$/.test(v) && !v.includes('*')) {
    return false;
  }
  // Exact branch or tag ref
  if (/^repo:[^:/]+\/[^:/]+:ref:refs\/(heads|tags)\/[^*]+$/.test(v) && !v.includes('*')) {
    return false;
  }
  // pull_request is a defined context (acceptable pin for some teams) — treat as pinned but still warn? 
  // Spec says warn when not pinned to branch/environment/tag. pull_request is neither → unpinned/warn.
  if (/^repo:[^:/]+\/[^:/]+:ref:refs\/heads\/[^*]+$/.test(v)) return false;

  return true;
}

function checkStringLike(doc, stmt, stmtPath) {
  const findings = [];
  const conditions = listConditions(stmt, stmtPath);
  for (const entry of conditions) {
    if (!/^StringLike$/i.test(entry.operator)) continue;
    if (!entry.key.includes(GITHUB_OIDC_HOST)) continue;
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
  return s <= t; // critical=0 is highest
}
