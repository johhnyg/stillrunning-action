# stillrunning GitHub Action

Scan your Python and Node.js dependencies for supply chain attacks, malicious packages, and typosquatting.

[![stillrunning](https://stillrunning.io/badge/protected)](https://stillrunning.io)

## Features

- Scans `requirements.txt`, `package.json`, `Pipfile`
- Detects known malicious packages (DPRK, typosquats, backdoors)
- AI-powered analysis for unknown packages (with token)
- Posts results as PR comments
- Fails CI/CD on dangerous packages

## Quick Start

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Scan dependencies
        uses: johhnyg/stillrunning-action@v1
        with:
          token: ${{ secrets.STILLRUNNING_TOKEN }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `token` | stillrunning.io API token for AI scanning | No | `''` |
| `files` | Comma-separated list of files to scan | No | `requirements.txt,requirements-dev.txt,package.json` |
| `fail-on-dangerous` | Fail workflow on dangerous packages | No | `true` |
| `fail-on-suspicious` | Fail workflow on suspicious packages | No | `false` |
| `comment-on-pr` | Post results as PR comment | No | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `result` | Scan result: `pass`, `warn`, or `fail` |
| `dangerous-count` | Number of dangerous packages found |
| `suspicious-count` | Number of suspicious packages found |

## Example: Full Configuration

```yaml
- name: Scan dependencies
  uses: johhnyg/stillrunning-action@v1
  with:
    token: ${{ secrets.STILLRUNNING_TOKEN }}
    files: 'requirements.txt,requirements-dev.txt,setup.py'
    fail-on-dangerous: 'true'
    fail-on-suspicious: 'false'
    comment-on-pr: 'true'
```

## Example: Matrix with Multiple Python Versions

```yaml
jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: johhnyg/stillrunning-action@v1
        with:
          token: ${{ secrets.STILLRUNNING_TOKEN }}

  test:
    needs: security  # Only run tests if security passes
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python: ['3.9', '3.10', '3.11']
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v4
        with:
          python-version: ${{ matrix.python }}
      - run: pip install -r requirements.txt
      - run: pytest
```

## Free vs Paid

| Feature | Free | With Token |
|---------|------|------------|
| Cached scans | 50/day per repo | Unlimited |
| Known malicious packages | Blocked | Blocked |
| Threat feed database | Checked | Checked |
| AI analysis of unknown packages | - | 100-10000/day |
| PR comments | Yes | Yes |

Get a token at [stillrunning.io/pricing](https://stillrunning.io/pricing)

## What It Detects

- **Known malicious packages**: Packages in our threat database (DPRK campaigns, typosquats, backdoors)
- **Typosquatting**: Packages with names similar to popular packages
- **AI-flagged packages**: Obfuscated code, credential harvesting, reverse shells

## PR Comment Example

When a dangerous package is found:

> ## 🛡️ stillrunning Security Scan
>
> Scanned **15** packages in `owner/repo`
>
> ### ❌ Scan Failed — Dangerous packages detected
>
> | Package | Version | Status | Score | Details |
> |---------|---------|--------|-------|---------|
> | requests | 2.31.0 | ✅ CLEAN | 0 | Package verified |
> | evil-pkg | 1.0.0 | 🚫 DANGEROUS | 95 | Known malicious package |
>
> **Summary:** 14 clean, 0 suspicious, 1 dangerous, 0 unknown

## License

MIT

## Links

- [stillrunning.io](https://stillrunning.io)
- [Documentation](https://stillrunning.io/docs)
- [Threat Database](https://stillrunning.io/threats)
