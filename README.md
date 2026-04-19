# stillrunning GitHub Action v3

Supply chain attack protection for your CI/CD pipeline.

[![stillrunning](https://stillrunning.io/badge/protected)](https://stillrunning.io)

> **Note:** Use directly via `johhnyg/stillrunning-action@v3` (not yet listed in GitHub Marketplace)

## What's new in v3

- **Blocklist check first** — fast, free, checks 100+ known malicious packages
- **Yanked package detection** — fails if package was removed from PyPI
- **Community reporting** — DANGEROUS packages automatically reported to protect others
- **Clean summary output** — easy to read security report

## Quick start

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: johhnyg/stillrunning-action@v3
```

## Example output

```
========================================
stillrunning Security Report
========================================

  Packages checked: 47
  All packages clean

========================================
```

Or if issues found:

```
========================================
stillrunning Security Report
========================================

  Packages checked: 47
  Suspicious (review): 1
  Dangerous (blocked): 1
  Blocklist hits: 1

  BLOCKED: malicious-pkg==1.0.0
     Score: 95/100
     Reason: Credential harvesting detected
     Action: Remove from requirements.txt

========================================
```

## Inputs

| Input | Description | Default |
|-------|-------------|---------|
| `token` | stillrunning.io API token (enables AI scanning) | `''` |
| `files` | Dependency files to scan | `requirements.txt,...` |
| `scan-imports` | Scan Python import statements | `true` |
| `python-paths` | Paths to scan for imports | `**/*.py` |
| `fail-on-dangerous` | Fail if dangerous packages found | `true` |
| `fail-on-suspicious` | Fail if suspicious packages found | `false` |
| `comment-on-pr` | Post results as PR comment | `true` |

## Outputs

| Output | Description |
|--------|-------------|
| `result` | `pass`, `warn`, or `fail` |
| `dangerous-count` | Number of dangerous packages |
| `suspicious-count` | Number of suspicious packages |
| `blocklist-hits` | Packages found in blocklist |
| `yanked-count` | Yanked packages found |

## How it works

1. **Blocklist check** (instant) — checks against 100+ known malicious packages
2. **Yanked detection** (fast) — verifies packages weren't removed from PyPI
3. **AI scanning** (with token) — deep analysis of unknown packages

## Examples

### Basic scan

```yaml
- uses: johhnyg/stillrunning-action@v3
```

### With AI scanning

```yaml
- uses: johhnyg/stillrunning-action@v3
  with:
    token: ${{ secrets.STILLRUNNING_TOKEN }}
```

### Strict mode

```yaml
- uses: johhnyg/stillrunning-action@v3
  with:
    fail-on-dangerous: 'true'
    fail-on-suspicious: 'true'
```

## Links

- [stillrunning.io](https://stillrunning.io)
- [Get API token](https://stillrunning.io/pricing)
- [Threat Database](https://stillrunning.io/threats)
- [@bit_bot9000](https://x.com/bit_bot9000)

## License

MIT
