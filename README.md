# oidc-trust-lint

Lint **AWS IAM role trust policy** JSON files for **GitHub Actions OIDC** misconfigurations.

Offline only: policy files in, findings out. No AWS account, no credentials, no network. Zero npm runtime dependencies. Node 20. MIT licensed.

Built as a personal DevSecOps portfolio project (CLI + composite GitHub Action).

## Why

A trust policy that federates `token.actions.githubusercontent.com` without a tight `sub` / `aud` condition can let the wrong workflow (or the wrong repository) assume a privileged role. This tool reviews the JSON you already keep in git and fails CI when the trust is too broad.

## Rules

| ID | Severity | What it catches |
| --- | --- | --- |
| `OIDC_AUD_MISSING` | critical | No `token.actions.githubusercontent.com:aud` condition |
| `OIDC_AUD_WRONG` | critical | `aud` present but not `sts.amazonaws.com` |
| `OIDC_SUB_MISSING` | critical | No `sub` condition (any repo that can get a token may assume) |
| `OIDC_SUB_WILDCARD_ANY` | critical | `sub` like `repo:*` (any org/repo on GitHub) |
| `OIDC_SUB_WILDCARD_ORG` | high | `sub` like `repo:org/*` (any repo in an org) |
| `OIDC_PRINCIPAL_WRONG` | critical | Missing / wildcard / non-ARN Federated principal |
| `OIDC_RISKY_PRINCIPALS` | high | `sts:AssumeRoleWithWebIdentity` combined with other principals (e.g. `AWS: *`) |
| `OIDC_STRINGLIKE_UNNECESSARY` | medium | `StringLike` used when values have no `*` / `?` |
| `OIDC_SUB_UNPINNED` | low | `sub` not pinned to a concrete branch, tag, or environment |

Only statements that look like GitHub OIDC trust (Federated principal or condition keys for `token.actions.githubusercontent.com`) are evaluated. EC2/Lambda/etc. trust policies are ignored.

### Bad vs fixed

**Bad** — missing `sub` (any GitHub identity that presents a token for this audience can assume):

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
    }
  }
}
```

**Fixed** — pin org, repo, and branch:

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
      "token.actions.githubusercontent.com:sub": "repo:acme/widgets:ref:refs/heads/main"
    }
  }
}
```

**Bad** — org-wide wildcard:

```json
"token.actions.githubusercontent.com:sub": "repo:acme/*"
```

**Fixed** — single repository (and prefer a ref/environment pin):

```json
"token.actions.githubusercontent.com:sub": "repo:acme/widgets:environment:production"
```

## Usage (CLI)

```bash
node src/cli.js path/to/policies --fail-on high
node src/cli.js path/to/policies --format json -o report.json
node src/cli.js path/to/policies --format sarif --sarif oidc-trust-lint.sarif
```

| Flag | Default | Meaning |
| --- | --- | --- |
| `--format` / `-f` | `text` | `text`, `json`, or `sarif` on stdout |
| `--fail-on` | `high` | Exit `1` on findings at/above this severity (`critical`…`info`, or `none`) |
| `--out` / `-o` | — | Also write JSON |
| `--sarif` | — | Also write SARIF 2.1.0 (GitHub code scanning) |

Each finding includes: rule id, severity, file, JSON path, message, and a fix suggestion.

## Usage (GitHub Action)

Pin this action (and every third-party action) to a **full commit SHA**.

```yaml
# .github/workflows/oidc-trust-lint.yml
name: oidc-trust-lint
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  # Add security-events: write only when you also upload the SARIF with a
  # SHA-pinned github/codeql-action/upload-sarif step.

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          persist-credentials: false
      - uses: dhivagar29/oidc-trust-lint@<full-commit-sha>
        with:
          path: policies
          fail-on: high
          sarif-path: oidc-trust-lint.sarif
```

Inputs: `path`, `format`, `fail-on`, `sarif-path`, `json-path`. Outputs: `finding-count`, `sarif-path`, `json-path`.

## Supported inputs

| Format | How it is detected |
| --- | --- |
| Plain IAM trust policy JSON | Top-level `Statement` (or a bare statement / statement array) |
| Terraform JSON | `resource.aws_iam_role.*.assume_role_policy` (stringified JSON or object) |
| CloudFormation JSON | `Resources.*.Type == AWS::IAM::Role` → `Properties.AssumeRolePolicyDocument` |

## Limits

- **JSON only.** HCL (`.tf`), YAML CloudFormation, and CDK/Pulumi sources are out of scope unless you export JSON first.
- **No live AWS.** The tool never calls STS/IAM and cannot see roles that exist only in an account.
- **GitHub OIDC only.** Other IdPs (ADFS, Cognito, GitLab, etc.) are not evaluated.
- **Heuristic CFN/TF extraction.** Nested modules, `templatefile()`, `aws_iam_policy_document` data sources, and Fn::Sub-only documents may not be fully expanded.
- **Line numbers.** SARIF locations point at the file (JSON path is in the result properties / region message), not a precise byte offset.
- **`pull_request` subject.** A `sub` of `repo:org/name:pull_request` is treated as unpinned relative to branch/tag/environment guidance (severity `low`).

## Sample output

See [`docs/sample-output.txt`](docs/sample-output.txt) and [`docs/sample.sarif`](docs/sample.sarif), generated by running the tool against `test/fixtures`.

## Develop

```bash
npm test
npm run sample
```

CI runs the same tests on every push/PR (`.github/workflows/ci.yml`) with least-privilege `permissions: contents: read` and SHA-pinned actions.

## License

MIT © dhivagar29
