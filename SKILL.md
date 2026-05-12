---
name: npm-supply-chain-audit
description: Scan npm projects for compromised packages from known supply chain attacks (Mini Shai-Hulud campaign targeting TanStack, Mistral, UiPath, and 160+ other packages). Use this skill whenever the user asks about npm supply chain security, wants to check if their dependencies are compromised, mentions the Mini Shai-Hulud attack, TanStack compromise, or asks to audit npm packages for malware. Also trigger when the user asks to scan a project for malicious npm packages, check lockfiles for known bad versions, or run a dependency security audit against a specific advisory.
---

# npm Supply Chain Audit

Scan any npm project's dependencies (direct and transitive) against a curated list of packages compromised in the Mini Shai-Hulud supply chain campaign.

## What this catches

The bundled `references/compromised-packages.json` contains 373 malicious package-version entries across 169 npm packages, including `@tanstack/*`, `@mistralai/*`, `@squawk/*`, `@uipath/*`, `@tallyui/*`, `@beproduct/*`, and several unscoped packages. The malware steals npm tokens, GitHub tokens, cloud credentials, and Kubernetes secrets from developer machines and CI/CD runners.

The compromised list is a snapshot — check the [Aikido advisory](https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised) for the latest updates and update the JSON file as needed.

## How to run the audit

The skill bundles a zero-dependency Node.js script at `scripts/audit.mjs`. Run it with:

```bash
node <skill-path>/scripts/audit.mjs --dir <project-directory>
```

### Options

- `--dir <path>` — Project directory to scan (default: current directory). Monorepo workspaces are discovered automatically.
- `--packages <path>` — Path to a custom compromised-packages JSON file. Defaults to the bundled `references/compromised-packages.json`.
- `--json` — Output structured JSON instead of a human-readable report. Useful for piping into other tools or CI integrations.
- `--ci` — Exit with code 1 if any compromised packages are found. Combine with `--json` for machine-readable CI gates.

### What it scans

The script reads all of these if present:
- `package.json` — direct dependencies (all groups)
- `package-lock.json` — transitive dependencies (lockfile v1, v2, v3)
- `yarn.lock` — transitive dependencies (v1 and berry)
- `pnpm-lock.yaml` — transitive dependencies (v5, v6+)

For monorepos, it automatically discovers workspace directories from the root `package.json` `workspaces` field.

## Interpreting results

### Clean result
If no compromised packages are found, report this to the user and recommend they re-run periodically since the advisory list is actively growing.

### Affected result
If compromised packages are found, the report shows each affected package with:
- Whether it's a direct or transitive dependency
- Which lockfile it was found in
- All known compromised versions for that package

Emphasize these remediation steps to the user:
1. **Remove or downgrade** the affected packages immediately
2. **Run `npm audit`** for any additional advisories
3. **Rotate credentials** — npm tokens, GitHub tokens, cloud API keys, and any secrets that were accessible on the machine or in CI where the compromised package was installed
4. **Check CI/CD logs** for unexpected outbound network activity
5. **Review the advisory** for indicators of compromise (IOCs)

## Updating the compromised packages list

The `references/compromised-packages.json` file can be updated independently of the skill. The format is:

```json
{
  "_meta": {
    "advisory": "Description of the advisory",
    "source": "URL to the advisory",
    "last_updated": "YYYY-MM-DD"
  },
  "packages": {
    "@scope/package-name": ["1.0.0", "1.0.1"],
    "unscoped-package": ["2.0.0"]
  }
}
```

You can also point `--packages` at a completely different JSON file to audit against a separate advisory or custom blocklist. The `_meta` field is optional — the script only requires a `packages` object (or a flat object of package-name → version-array).
