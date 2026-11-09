#!/usr/bin/env node
/**
 * CLI: lint AWS IAM trust policy JSON for GitHub Actions OIDC misconfigurations.
 *
 *   node src/cli.js [paths...] [--format text|json|sarif] [--fail-on SEVERITY]
 *                   [--out FILE] [--sarif FILE]
 */
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  lintPaths,
  shouldFail,
  formatHuman,
  formatJson,
  formatSarif,
  SEVERITY_ORDER,
} from './index.js';

function parseArgs(argv) {
  const args = {
    paths: [],
    format: 'text',
    failOn: 'high',
    out: null,
    sarif: null,
    help: false,
  };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = argv[i + 1];
    if (a === '--format' || a === '-f') {
      args.format = String(next || '').toLowerCase();
      i++;
    } else if (a === '--fail-on') {
      args.failOn = String(next || '').toLowerCase();
      i++;
    } else if (a === '--out' || a === '-o') {
      args.out = next;
      i++;
    } else if (a === '--sarif') {
      args.sarif = next;
      i++;
    } else if (a === '--help' || a === '-h') {
      args.help = true;
    } else if (a.startsWith('-')) {
      throw new Error(`Unknown argument: ${a}`);
    } else {
      args.paths.push(a);
    }
  }
  return args;
}

function printHelp() {
  process.stdout.write(`oidc-trust-lint — lint AWS IAM trust policies for GitHub Actions OIDC issues

Usage:
  oidc-trust-lint [options] <file-or-dir>...

Options:
  -f, --format text|json|sarif   Primary stdout format (default: text)
  --fail-on SEVERITY             Exit 1 when findings at/above this level
                                 (critical|high|medium|low|info|none; default: high)
  -o, --out FILE                 Also write JSON report to FILE
  --sarif FILE                   Also write SARIF 2.1.0 to FILE
  -h, --help                     Show help

Notes:
  Offline only. Reads local JSON policy files. No AWS API calls, no credentials.
`);
}

function writeFile(filePath, contents) {
  const abs = path.resolve(filePath);
  fs.mkdirSync(path.dirname(abs), { recursive: true });
  fs.writeFileSync(abs, contents);
}

export function run(argv = process.argv) {
  const args = parseArgs(argv);
  if (args.help) {
    printHelp();
    return { exitCode: 0 };
  }
  if (!args.paths.length) {
    throw new Error('Pass at least one file or directory to lint');
  }
  if (!['text', 'json', 'sarif'].includes(args.format)) {
    throw new Error(`Invalid --format: ${args.format}`);
  }
  const allowedFail = new Set([...SEVERITY_ORDER, 'none']);
  if (!allowedFail.has(args.failOn)) {
    throw new Error(`Invalid --fail-on: ${args.failOn}`);
  }

  const { findings, filesScanned, errors } = lintPaths(args.paths);
  const cwd = process.cwd();

  let primary;
  if (args.format === 'json') {
    primary = formatJson(findings, { filesScanned: filesScanned.length, cwd });
  } else if (args.format === 'sarif') {
    primary = formatSarif(findings, { cwd });
  } else {
    primary = formatHuman(findings, { cwd });
  }

  if (args.out) {
    writeFile(args.out, formatJson(findings, { filesScanned: filesScanned.length, cwd }));
  }
  if (args.sarif) {
    writeFile(args.sarif, formatSarif(findings, { cwd }));
  }

  process.stdout.write(primary);

  if (errors.length) {
    for (const e of errors) {
      process.stderr.write(`oidc-trust-lint: error reading ${e.file}: ${e.error}\n`);
    }
  }

  const fail = shouldFail(findings, args.failOn) || errors.length > 0;
  return {
    exitCode: fail ? 1 : 0,
    findings,
    filesScanned,
    errors,
  };
}

const isMain = process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url));

if (isMain) {
  try {
    const result = run(process.argv);
    process.exitCode = result.exitCode;
  } catch (err) {
    process.stderr.write(`oidc-trust-lint: ${err.message || err}\n`);
    process.exitCode = 2;
  }
}
