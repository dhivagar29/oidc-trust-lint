/**
 * Output formatters: human text, JSON, SARIF 2.1.0
 */
import path from 'node:path';
import { RULES, SEVERITY_ORDER } from './rules.js';

/**
 * @param {import('./rules.js').Finding[]} findings
 * @param {{ cwd?: string }} [opts]
 */
export function formatHuman(findings, opts = {}) {
  const cwd = opts.cwd || process.cwd();
  if (!findings.length) {
    return 'oidc-trust-lint: no findings\n';
  }
  const lines = [];
  lines.push(`oidc-trust-lint: ${findings.length} finding(s)`);
  lines.push('');
  for (const f of findings) {
    const rel = relativize(f.file, cwd);
    lines.push(`[${f.severity.toUpperCase()}] ${f.ruleId}`);
    lines.push(`  file:    ${rel}`);
    lines.push(`  path:    ${f.jsonPath}`);
    lines.push(`  message: ${f.message}`);
    lines.push(`  fix:     ${f.fix}`);
    lines.push('');
  }
  return lines.join('\n');
}

/**
 * @param {import('./rules.js').Finding[]} findings
 * @param {{ filesScanned?: number, cwd?: string }} [meta]
 */
export function formatJson(findings, meta = {}) {
  const cwd = meta.cwd || process.cwd();
  return JSON.stringify(
    {
      tool: 'oidc-trust-lint',
      version: '1.0.0',
      filesScanned: meta.filesScanned ?? null,
      findingCount: findings.length,
      findings: findings.map((f) => ({
        ...f,
        file: relativize(f.file, cwd),
      })),
    },
    null,
    2,
  ) + '\n';
}

/**
 * SARIF 2.1.0 suitable for GitHub code scanning upload.
 * @param {import('./rules.js').Finding[]} findings
 * @param {{ cwd?: string }} [opts]
 */
export function formatSarif(findings, opts = {}) {
  const cwd = opts.cwd || process.cwd();
  const rules = Object.values(RULES).map((r) => ({
    id: r.id,
    name: r.id,
    shortDescription: { text: r.title },
    fullDescription: { text: r.title },
    defaultConfiguration: {
      level: sarifLevel(r.severity),
    },
    properties: {
      severity: r.severity,
      tags: ['security', 'oidc', 'aws', 'iam', 'github-actions'],
    },
  }));

  const results = findings.map((f) => ({
    ruleId: f.ruleId,
    level: sarifLevel(f.severity),
    message: { text: `${f.message} Fix: ${f.fix}` },
    locations: [
      {
        physicalLocation: {
          artifactLocation: {
            uri: toUri(relativize(f.file, cwd)),
          },
          region: {
            startLine: 1,
            message: { text: f.jsonPath },
          },
        },
      },
    ],
    properties: {
      jsonPath: f.jsonPath,
      severity: f.severity,
      fix: f.fix,
    },
  }));

  const sarif = {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'oidc-trust-lint',
            version: '1.0.0',
            informationUri: 'https://github.com/dhivagar29/oidc-trust-lint',
            rules,
          },
        },
        results,
      },
    ],
  };
  return JSON.stringify(sarif, null, 2) + '\n';
}

function sarifLevel(severity) {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

function relativize(file, cwd) {
  if (!file || file === '<memory>') return file;
  const rel = path.relative(cwd, file);
  return rel && !rel.startsWith('..') ? rel : file;
}

function toUri(p) {
  return p.split(path.sep).join('/');
}

export function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const sa = SEVERITY_ORDER.indexOf(a.severity);
    const sb = SEVERITY_ORDER.indexOf(b.severity);
    if (sa !== sb) return sa - sb;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    if (a.ruleId !== b.ruleId) return a.ruleId.localeCompare(b.ruleId);
    return a.jsonPath.localeCompare(b.jsonPath);
  });
}
