# npm Supply Chain Audit

Scan any npm project's dependencies (direct and transitive) against a curated list of packages compromised in the [Mini Shai-Hulud supply chain campaign](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised).

**373 malicious package-version entries across 169 npm packages**, including `@tanstack/*`, `@mistralai/*`, `@squawk/*`, `@uipath/*`, `@tallyui/*`, `@beproduct/*`, and several unscoped packages.

Zero external dependencies — uses only Node.js built-ins.

## Quick Start

```bash
# Run against current directory
npx npm-supply-chain-audit

# Run against a specific project
npx npm-supply-chain-audit --dir /path/to/project

# JSON output
npx npm-supply-chain-audit --dir /path/to/project --json

# CI mode — exits with code 1 if compromised packages found
npx npm-supply-chain-audit --dir /path/to/project --ci
```

## Install Locally

```bash
git clone https://github.com/demiurge28/npm-supply-chain-audit.git
cd npm-supply-chain-audit
node scripts/audit.mjs --dir /path/to/your/project
```

## Options

| Flag | Description |
|------|-------------|
| `--dir <path>` | Project directory to scan (default: `.`). Monorepo workspaces are discovered automatically. |
| `--packages <path>` | Path to a custom compromised-packages JSON file. Defaults to the bundled list. |
| `--json` | Output structured JSON instead of a human-readable report. |
| `--ci` | Exit with code 1 if any compromised packages are found. |
| `--help` | Show usage information. |

## What It Scans

- `package.json` — direct dependencies (all groups)
- `package-lock.json` — transitive dependencies (lockfile v1, v2, v3)
- `yarn.lock` — transitive dependencies (v1 and berry)
- `pnpm-lock.yaml` — transitive dependencies (v5, v6+)

For monorepos, it automatically discovers workspace directories from the root `package.json` `workspaces` field.

## CI Integration

### GitHub Actions

```yaml
- name: npm supply chain audit
  run: npx npm-supply-chain-audit --dir . --ci
```

Or add as a dedicated workflow:

```yaml
name: Supply Chain Audit

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * *"

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

## Git Hook (Pre-Push)

Use the setup script to add a pre-push hook to any repo:

```bash
# From this repo
./setup.sh /path/to/target-repo

# Or manually add to .git/hooks/pre-push:
npx npm-supply-chain-audit --dir . --ci
```

The setup script is idempotent — safe to run multiple times.

## Updating the Compromised Packages List

The list in `references/compromised-packages.json` is a snapshot from the [Aikido advisory](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised). The advisory is actively growing.

To update, edit the JSON directly or point `--packages` at a different file:

```json
{
  "_meta": {
    "advisory": "Description",
    "source": "https://...",
    "last_updated": "YYYY-MM-DD"
  },
  "packages": {
    "@scope/name": ["1.0.0", "1.0.1"],
    "unscoped-name": ["2.0.0"]
  }
}
```

## License

MIT
