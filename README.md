# npm Supply Chain Audit

Scan any npm project's dependencies (direct and transitive) against a curated list of packages compromised in the [Mini Shai-Hulud supply chain campaign](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised).

**373 malicious package-version entries across 169 npm packages**, including `@tanstack/*`, `@mistralai/*`, `@squawk/*`, `@uipath/*`, `@tallyui/*`, `@beproduct/*`, and several unscoped packages. The malware steals npm tokens, GitHub tokens, cloud credentials, and Kubernetes secrets from developer machines and CI/CD runners.

Zero external dependencies — uses only Node.js built-ins (requires Node.js 18+).

## Quick Start

The fastest way to scan a project:

```bash
# Scan the current directory
npx npm-supply-chain-audit

# Scan a specific project
npx npm-supply-chain-audit --dir /path/to/project
```

## Installation

### Option 1: Run directly with npx (no install)

```bash
npx npm-supply-chain-audit --dir .
```

### Option 2: Install globally

```bash
npm install -g npm-supply-chain-audit
npm-supply-chain-audit --dir /path/to/project
```

### Option 3: Clone the repo

```bash
git clone https://github.com/demiurge28/npm-supply-chain-audit.git
cd npm-supply-chain-audit
node scripts/audit.mjs --dir /path/to/project
```

### Option 4: Add as a dev dependency

```bash
npm install --save-dev npm-supply-chain-audit
```

Then add to your `package.json` scripts:

```json
{
  "scripts": {
    "security:audit": "npm-supply-chain-audit --dir . --ci"
  }
}
```

## Usage

```
npm-supply-chain-audit [options]

Options:
  --dir <path>        Project directory to scan (default: .)
  --packages <path>   Path to a custom compromised-packages JSON (default: bundled list)
  --json              Output structured JSON instead of a human-readable report
  --ci                Exit with code 1 if any compromised packages are found
  --help              Show usage information
```

### Examples

```bash
# Human-readable report
npm-supply-chain-audit --dir ./my-app

# JSON output (for piping into other tools)
npm-supply-chain-audit --dir ./my-app --json

# CI gate — fails the build if compromised packages are found
npm-supply-chain-audit --dir ./my-app --ci

# Combine JSON + CI mode
npm-supply-chain-audit --dir ./my-app --json --ci

# Use a custom compromised-packages list
npm-supply-chain-audit --dir ./my-app --packages /path/to/custom-list.json
```

### Exit Codes

- **0** — No compromised packages found (or findings found without `--ci`)
- **1** — Compromised packages found (only with `--ci`)
- **2** — Runtime error (missing directory, invalid JSON, etc.)

## What It Scans

The tool reads all of the following files if present in the target directory:

- **`package.json`** — direct dependencies across all groups (`dependencies`, `devDependencies`, `optionalDependencies`, `peerDependencies`)
- **`package-lock.json`** — transitive dependencies (supports lockfile v1, v2, and v3)
- **`yarn.lock`** — transitive dependencies (supports yarn classic and berry)
- **`pnpm-lock.yaml`** — transitive dependencies (supports v5 and v6+)

For **monorepos**, it automatically discovers workspace packages from the root `package.json` `workspaces` field and scans each one.

## Example Output

### Clean project

```
═══════════════════════════════════════════════════════════════
  npm Supply Chain Audit Report — Mini Shai-Hulud Campaign
═══════════════════════════════════════════════════════════════

Advisory:     Mini Shai-Hulud npm supply chain attack
Source:       https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
List updated: 2026-05-12
Scan time:    2026-05-12T14:30:18.980Z

── /path/to/project
   Dependencies scanned: 342
   Status: ✅ CLEAN — no compromised packages found

───────────────────────────────────────────────────────────────
No compromised packages detected. Stay vigilant — the
advisory list is still growing. Re-run periodically.
───────────────────────────────────────────────────────────────
```

### Affected project

```
── /path/to/project
   Dependencies scanned: 587
   Status: 🚨 AFFECTED — 2 compromised package(s) found

   ⚠  @tanstack/react-router@1.169.5 [DIRECT]
      Found in: package.json (dependencies)
      Known bad versions: 1.169.5, 1.169.8
   ⚠  @tanstack/router-core@1.169.8 [TRANSITIVE]
      Found in: package-lock.json
      Known bad versions: 1.169.5, 1.169.8

───────────────────────────────────────────────────────────────
RECOMMENDED ACTIONS:
  1. Remove or downgrade affected packages immediately
  2. Run `npm audit` for additional advisories
  3. Rotate any npm, GitHub, and cloud tokens/credentials
     that may have been exposed on this machine or in CI
  4. Check CI/CD logs for unexpected network activity
  5. Review the advisory for IOCs:
     https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised
───────────────────────────────────────────────────────────────
```

### JSON output

```json
{
  "timestamp": "2026-05-12T14:30:23.526Z",
  "advisory": {
    "advisory": "Mini Shai-Hulud npm supply chain attack",
    "source": "https://www.aikido.dev/blog/...",
    "last_updated": "2026-05-12"
  },
  "results": [
    {
      "projectDir": "/path/to/project",
      "totalDepsScanned": 342,
      "findings": [],
      "status": "CLEAN"
    }
  ],
  "summary": {
    "projectsScanned": 1,
    "totalDepsScanned": 342,
    "totalFindings": 0
  }
}
```

## CI Integration

### GitHub Actions (single step)

Add to any existing workflow:

```yaml
- name: npm supply chain audit
  run: npx npm-supply-chain-audit --dir . --ci
```

### GitHub Actions (dedicated workflow)

Create `.github/workflows/supply-chain-audit.yml`:

```yaml
name: Supply Chain Audit

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    # Run daily — the advisory list is still growing
    - cron: "0 6 * * *"
  workflow_dispatch:

permissions:
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "20"
      - run: npx npm-supply-chain-audit --dir . --ci
```

### GitLab CI

```yaml
supply-chain-audit:
  image: node:20
  script:
    - npx npm-supply-chain-audit --dir . --ci
  rules:
    - if: $CI_PIPELINE_SOURCE == "merge_request_event"
    - if: $CI_COMMIT_BRANCH == "main"
```

### Taskfile

```yaml
tasks:
  security:audit:
    desc: Scan npm dependencies for compromised packages
    cmds:
      - npx npm-supply-chain-audit --dir . --ci
```

## Git Hook (Pre-Push)

Block pushes if compromised packages are detected.

### Automatic setup

```bash
# Install the hook into any git repo
./setup.sh /path/to/target-repo
```

The setup script is idempotent — safe to run multiple times. It appends to an existing `pre-push` hook without overwriting it.

### Manual setup

Add to `.git/hooks/pre-push` (or your hook manager of choice):

```bash
#!/bin/sh
npx --yes npm-supply-chain-audit --dir "$(git rev-parse --show-toplevel)" --ci
if [ $? -ne 0 ]; then
  echo "❌ Compromised npm packages detected. Push blocked."
  exit 1
fi
```

## Updating the Compromised Packages List

The bundled list in `references/compromised-packages.json` is a snapshot from the [Aikido advisory](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised) dated 2026-05-12. **The advisory is actively growing** — check the source for updates.

To update, edit the JSON file directly or point `--packages` at a custom file. The format:

```json
{
  "_meta": {
    "advisory": "Description of the advisory",
    "source": "https://link-to-advisory",
    "last_updated": "YYYY-MM-DD"
  },
  "packages": {
    "@scope/package-name": ["1.0.0", "1.0.1"],
    "unscoped-package": ["2.0.0"]
  }
}
```

The `_meta` field is optional — a flat object mapping package names to version arrays also works:

```json
{
  "@scope/name": ["1.0.0"],
  "other-pkg": ["2.0.0", "2.0.1"]
}
```

## Project Structure

```
npm-supply-chain-audit/
├── scripts/
│   └── audit.mjs                         # Main audit script (zero dependencies)
├── references/
│   └── compromised-packages.json         # 169 packages, 373 malicious versions
├── tests/
│   ├── audit.test.mjs                    # Test suite (65 tests, node:test)
│   └── fixtures/                         # Test fixtures for all lockfile formats
├── setup.sh                              # Git hook installer
├── SKILL.md                              # Warp AI skill definition
├── package.json
└── README.md
```

## Development

### Prerequisites

- Node.js 18+

### Running Tests

```bash
npm test
```

The test suite uses `node:test` (built into Node.js, no test framework to install) and covers:

- All dependency scanners (package.json, lockfile v1/v2/v3, yarn v1/berry, pnpm v5/v6+)
- Monorepo workspace discovery
- Compromised package detection and deduplication
- Report formatting (human-readable and JSON)
- CLI integration (exit codes, flags, custom package lists)

### Running the audit locally

```bash
# Against the tool's own dependencies (meta!)
node scripts/audit.mjs

# Against another project
node scripts/audit.mjs --dir /path/to/project
```

## Background

The Mini Shai-Hulud campaign is an npm supply chain attack that compromises legitimate packages by stealing developer credentials from build environments and using them to publish malicious versions. The malware targets:

- npm tokens
- GitHub tokens
- Cloud API keys and credentials
- Kubernetes service account tokens
- Deployment secrets

Affected scopes include `@tanstack`, `@mistralai`, `@squawk`, `@uipath`, `@tallyui`, `@beproduct`, `@draftlab`, `@draftauth`, `@taskflow-corp`, `@mesadev`, `@dirigible-ai`, `@ml-toolkit-ts`, `@supersurkhet`, and several unscoped packages.

For the full advisory and IOCs, see the [Aikido blog post](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised).

## License

MIT
