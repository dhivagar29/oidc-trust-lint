# oidc-trust-lint

Lint **AWS IAM role trust policy** JSON files for **GitHub Actions OIDC** misconfigurations.

Offline only: policy files in, findings out. No AWS account, no credentials, no network. Zero npm runtime dependencies. Node 20. MIT licensed.

Built as a personal DevSecOps portfolio project (CLI + composite GitHub Action).

## Why

A trust policy that federates `token.actions.githubusercontent.com` without a tight `sub` / `aud` condition can let the wrong workflow (or the wrong repository) assume a privileged role. This tool reviews the JSON you already keep in git and fails CI when the trust is too broad.

## Rules

| ID | Severity | What it catches |
| --- | --- | --- |
| `OIDC_AUD_MISSING` | critical | No positive `aud` condition |
| `OIDC_AUD_WRONG` | critical | `aud` present but not `sts.amazonaws.com` |
| `OIDC_SUB_MISSING` | critical | No positive `sub` condition (`StringEquals`/`StringLike`); also when only `StringNot*` exists |
| `OIDC_SUB_FORALLVALUES` | critical | `ForAllValues:` on `sub` — true when the key is absent on single-valued claims, so it is not a real restriction |
| `OIDC_SUB_WILDCARD_ANY` | critical | `sub` like `repo:*`, or a wildcard in the org segment before `/` (e.g. `repo:myorg*` spans `myorg-evil/...`); `?` counts like `*` |
| `OIDC_SUB_WILDCARD_ORG` | high | `sub` like `repo:org/*` (any repo in a fixed org) |
| `OIDC_PRINCIPAL_WRONG` | critical | Missing / wildcard / non-ARN Federated principal |
| `OIDC_RISKY_PRINCIPALS` | high | `sts:AssumeRoleWithWebIdentity` combined with other principals (e.g. `AWS: *`) |
| `OIDC_STRINGLIKE_UNNECESSARY` | medium | `StringLike` used when values have no `*` / `?` |
| `OIDC_SUB_UNPINNED` | low | `sub` not pinned to a concrete branch, tag, or environment |
| `OIDC_SUB_LITERAL_WILDCARD` | low | `StringEquals` / `StringEqualsIgnoreCase` (incl. `ForAnyValue:`) with `*` or `?` in `sub` — treated as literals, so the role cannot be assumed; use `StringLike` with a pinned repo instead |

Only **Allow** statements that look like GitHub OIDC trust (Federated principal or condition keys for `token.actions.githubusercontent.com`) are evaluated. **Deny statements are skipped** and never count as the Allow's `sub`/`aud` restriction. EC2/Lambda/etc. trust policies are ignored. Condition keys and common string operators are matched case-insensitively. `ForAnyValue:` is treated as the plain operator; every array element of a `sub` value list is checked. Under `StringEquals` / `StringEqualsIgnoreCase`, `*` and `?` are literal characters (not wildcards) — see `OIDC_SUB_LITERAL_WILDCARD`.

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
- **Deny statements are not evaluated.** A sibling Deny with a tight `sub` does not satisfy an Allow that lacks one.
- **Custom `sub` claim templates.** Policies that pin non-default claims in `sub` (for example `repository_owner_id`, custom `job_workflow_ref` layouts, or enterprise claim customization) may trip `OIDC_SUB_UNPINNED` / wildcard rules incorrectly. Prefer the standard `repo:<org>/<repo>:...` shapes, or accept a false positive and document an exception.
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
