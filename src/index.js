/**
 * Public API: lint files or directories for GitHub Actions OIDC trust issues.
 */
import fs from 'node:fs';
import path from 'node:path';
import { findPolicyFiles } from './find-files.js';
import { loadPolicyDocs } from './parse.js';
import { lintPolicyDoc, severityAtOrAbove } from './rules.js';
import { sortFindings } from './format.js';

export { RULES, SEVERITY_ORDER, severityAtOrAbove } from './rules.js';
export { formatHuman, formatJson, formatSarif, sortFindings } from './format.js';
export { loadPolicyDocs, extractPolicies, isGitHubOidcStatement } from './parse.js';

/**
 * @param {string[]} inputs file or directory paths
 * @param {{ extensions?: string[] }} [opts]
 * @returns {{ findings: import('./rules.js').Finding[], filesScanned: string[], errors: { file: string, error: string }[] }}
 */
export function lintPaths(inputs, opts = {}) {
  const files = new Set();
  for (const input of inputs) {
    const abs = path.resolve(input);
    if (!fs.existsSync(abs)) {
      throw new Error(`Path does not exist: ${abs}`);
    }
    const st = fs.statSync(abs);
    if (st.isDirectory()) {
      for (const f of findPolicyFiles(abs, opts)) files.add(f);
    } else if (st.isFile()) {
      files.add(abs);
    }
  }

  const findings = [];
  const errors = [];
  const filesScanned = [...files].sort();

  for (const file of filesScanned) {
    try {
      const docs = loadPolicyDocs(file);
      for (const doc of docs) {
        findings.push(...lintPolicyDoc(doc));
      }
    } catch (err) {
      errors.push({ file, error: err.message || String(err) });
    }
  }

  return {
    findings: sortFindings(findings),
    filesScanned,
    errors,
  };
}

/**
 * @param {import('./rules.js').Finding[]} findings
 * @param {import('./rules.js').Severity} failOn
 */
export function shouldFail(findings, failOn) {
  if (!failOn || failOn === 'none') return false;
  return findings.some((f) => severityAtOrAbove(failOn, f.severity));
}
