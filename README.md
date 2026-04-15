# stillrunning GitHub Action v2

Scan your dependencies AND imports for supply chain attacks.

[![stillrunning](https://stillrunning.io/badge/protected)](https://stillrunning.io)

## Features (v2)

- **Dependency scanning**: requirements.txt, package.json, pyproject.toml, Pipfile
- **Import scanning**: Scan Python source files for import statements
- **Hash verification**: Verify packages against PyPI registry
- **AI analysis**: Claude-powered analysis for unknown packages (with token)
- **PR comments**: Post scan results directly on pull requests

## Quick start

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: johhnyg/stillrunning-action@v2
        with:
          fail-on-dangerous: 'true'
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `token` | stillrunning.io API token (enables AI scanning) | `''` |
| `files` | Dependency files to scan (comma-separated) | `requirements.txt,requirements-dev.txt,package.json,pyproject.toml` |
| `scan-imports` | Scan Python import statements | `true` |
| `python-paths` | Paths to scan for imports (glob patterns) | `**/*.py` |
| `verify-hashes` | Verify package hashes against PyPI | `true` |
| `fail-on-dangerous` | Fail if dangerous packages found | `true` |
| `fail-on-suspicious` | Fail if suspicious packages found | `false` |
| `comment-on-pr` | Post results as PR comment | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `result` | Scan result: `pass`, `warn`, or `fail` |
| `dangerous-count` | Number of dangerous packages |
| `suspicious-count` | Number of suspicious packages |
| `imports-scanned` | Number of import statements scanned |
| `packages-scanned` | Number of packages scanned |

## Examples

### Basic scan

```yaml
- uses: johhnyg/stillrunning-action@v2
```

### With AI scanning

```yaml
- uses: johhnyg/stillrunning-action@v2
  with:
    token: ${{ secrets.STILLRUNNING_TOKEN }}
```

### Strict mode (fail on suspicious)

```yaml
- uses: johhnyg/stillrunning-action@v2
  with:
    fail-on-dangerous: 'true'
    fail-on-suspicious: 'true'
```

### Scan specific paths

```yaml
- uses: johhnyg/stillrunning-action@v2
  with:
    files: 'requirements.txt,requirements-prod.txt'
    python-paths: 'src/**/*.py,tests/**/*.py'
```

### Skip import scanning

```yaml
- uses: johhnyg/stillrunning-action@v2
  with:
    scan-imports: 'false'
```

## What it checks

### Dependency files
- `requirements.txt` / `requirements-dev.txt`
- `package.json` (dependencies, devDependencies, peerDependencies)
- `pyproject.toml` (project.dependencies)
- `Pipfile` (packages, dev-packages)

### Import statements
Scans all `.py` files for:
- `import package`
- `from package import module`

Filters out standard library modules automatically.

### Hash verification
For each package:
1. Query PyPI for official SHA256 hash
2. Compare against downloaded package
3. Flag DANGEROUS if hashes don't match (tampered package)

## Verdicts

| Verdict | Description | Default Action |
|---------|-------------|----------------|
| CLEAN | Verified safe | Pass |
| SUSPICIOUS | Unusual behavior | Pass (warn) |
| DANGEROUS | Known malicious or tampered | Fail |

## PR Comment Example

When a dangerous package is found:

> ## stillrunning Security Scan
>
> Scanned **15** packages + **42** imports in `owner/repo`
>
> ### Scan Failed
>
> | Package | Status | Details |
> |---------|--------|---------|
> | requests | CLEAN | Hash verified |
> | evil-pkg | DANGEROUS | Known malicious |
>
> **Summary:** 14 clean, 0 suspicious, 1 dangerous

## Links

- [stillrunning.io](https://stillrunning.io)
- [Get API token](https://stillrunning.io/pricing)
- [Threat Database](https://stillrunning.io/threats)
- [@bit_bot9000](https://x.com/bit_bot9000)

## License

MIT
