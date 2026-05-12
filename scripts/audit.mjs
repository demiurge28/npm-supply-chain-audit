#!/usr/bin/env node

/**
 * npm Supply Chain Audit Script
 *
 * Scans a project's npm dependencies (direct and transitive) against a
 * known list of compromised packages from the Mini Shai-Hulud campaign.
 *
 * Usage:
 *   node audit.mjs --dir <project-dir> [--packages <compromised.json>] [--json] [--ci]
 *
 * Supports: package.json, package-lock.json (v2/v3), yarn.lock (v1+berry), pnpm-lock.yaml
 * Zero external dependencies — uses only Node.js built-ins.
 */

import { readFileSync, existsSync, readdirSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const DEFAULT_PACKAGES_PATH = join(
  __dirname,
  "..",
  "references",
  "compromised-packages.json"
);

// ---------------------------------------------------------------------------
// CLI argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const args = { dir: ".", packages: DEFAULT_PACKAGES_PATH, json: false, ci: false };
  for (let i = 2; i < argv.length; i++) {
    switch (argv[i]) {
      case "--dir":
        args.dir = argv[++i];
        break;
      case "--packages":
        args.packages = argv[++i];
        break;
      case "--json":
        args.json = true;
        break;
      case "--ci":
        args.ci = true;
        break;
      case "--help":
        console.log(
          `Usage: node audit.mjs --dir <project-dir> [--packages <compromised.json>] [--json] [--ci]

Options:
  --dir        Path to the project directory to scan (default: .)
  --packages   Path to compromised packages JSON (default: bundled list)
  --json       Output results as JSON
  --ci         Exit with code 1 if any compromised packages are found`
        );
        process.exit(0);
    }
  }
  return args;
}

// ---------------------------------------------------------------------------
// Load compromised packages list
// ---------------------------------------------------------------------------

function loadCompromisedPackages(filePath) {
  const raw = JSON.parse(readFileSync(resolve(filePath), "utf-8"));
  const packages = raw.packages ?? raw;
  // Normalize into a Map<string, Set<string>> for fast lookup
  const map = new Map();
  for (const [name, versions] of Object.entries(packages)) {
    map.set(name, new Set(versions));
  }
  return { map, meta: raw._meta ?? null };
}

// ---------------------------------------------------------------------------
// Dependency extractors — each returns Array<{ name, version, source, isDirect }>
// ---------------------------------------------------------------------------

function scanPackageJson(dir) {
  const filePath = join(dir, "package.json");
  if (!existsSync(filePath)) return [];
  const pkg = JSON.parse(readFileSync(filePath, "utf-8"));
  const results = [];
  for (const depGroup of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
    const deps = pkg[depGroup];
    if (!deps) continue;
    for (const [name, versionSpec] of Object.entries(deps)) {
      // Strip range prefixes (^, ~, >=, etc.) to get the base version
      const version = versionSpec.replace(/^[\^~>=<|! ]+/, "");
      results.push({ name, version, source: `package.json (${depGroup})`, isDirect: true });
    }
  }
  return results;
}

function scanPackageLockJson(dir) {
  const filePath = join(dir, "package-lock.json");
  if (!existsSync(filePath)) return [];
  const lock = JSON.parse(readFileSync(filePath, "utf-8"));
  const results = [];

  // lockfileVersion 2 & 3 use "packages" (path-keyed)
  if (lock.packages) {
    for (const [pkgPath, info] of Object.entries(lock.packages)) {
      if (!pkgPath || !info.version) continue; // skip root ""
      // Extract package name from the path: node_modules/@scope/name → @scope/name
      const name = pkgPath.replace(/^.*node_modules\//, "");
      results.push({ name, version: info.version, source: "package-lock.json", isDirect: false });
    }
  }

  // lockfileVersion 1 uses "dependencies" (nested)
  if (lock.dependencies) {
    const walk = (deps) => {
      for (const [name, info] of Object.entries(deps)) {
        if (info.version) {
          results.push({ name, version: info.version, source: "package-lock.json", isDirect: false });
        }
        if (info.dependencies) walk(info.dependencies);
      }
    };
    walk(lock.dependencies);
  }

  return results;
}

function scanYarnLock(dir) {
  const filePath = join(dir, "yarn.lock");
  if (!existsSync(filePath)) return [];
  const content = readFileSync(filePath, "utf-8");
  const results = [];

  // Matches both yarn v1 and berry formats:
  //   "package@^version":        (v1)
  //   "package@npm:^version":    (berry)
  //     version "1.2.3"          or  version: 1.2.3
  const entryRe = /^"?(@?[^@\n]+)@[^:]*:?\n/gm;
  const versionRe = /^\s+version[: ]+"?([^"\n]+)"?/gm;

  let entryMatch;
  while ((entryMatch = entryRe.exec(content)) !== null) {
    const name = entryMatch[1].replace(/^"/, "");
    // Find the next version line after this entry
    versionRe.lastIndex = entryMatch.index;
    const versionMatch = versionRe.exec(content);
    if (versionMatch) {
      results.push({ name, version: versionMatch[1], source: "yarn.lock", isDirect: false });
    }
  }
  return results;
}

function scanPnpmLock(dir) {
  const filePath = join(dir, "pnpm-lock.yaml");
  if (!existsSync(filePath)) return [];
  const content = readFileSync(filePath, "utf-8");
  const results = [];

  // pnpm-lock.yaml uses formats like:
  //   /@scope/name@1.2.3:     (v5)
  //   /@scope/name/1.2.3:     (v6+)
  //   /name@1.2.3:
  const re = /^\s+'?\/?(@?[^@/\n(]+(?:\/[^@/\n(]+)?)[@/](\d+\.\d+[^:'"\n]*)/gm;
  let match;
  while ((match = re.exec(content)) !== null) {
    results.push({ name: match[1], version: match[2], source: "pnpm-lock.yaml", isDirect: false });
  }
  return results;
}

// ---------------------------------------------------------------------------
// Recursive project discovery — find all package.json dirs in a monorepo
// ---------------------------------------------------------------------------

function discoverProjectDirs(rootDir) {
  const dirs = new Set([resolve(rootDir)]);

  // Check for workspace patterns in root package.json
  const rootPkg = join(rootDir, "package.json");
  if (existsSync(rootPkg)) {
    try {
      const pkg = JSON.parse(readFileSync(rootPkg, "utf-8"));
      if (Array.isArray(pkg.workspaces)) {
        // Simple glob: expand "packages/*" by checking subdirectories
        for (const pattern of pkg.workspaces) {
          const base = pattern.replace(/\/?\*.*$/, "");
          const baseDir = join(rootDir, base);
          if (existsSync(baseDir)) {
            try {
              for (const entry of readdirSync(baseDir, { withFileTypes: true })) {
                if (entry.isDirectory()) {
                  const candidateDir = join(baseDir, entry.name);
                  if (existsSync(join(candidateDir, "package.json"))) {
                    dirs.add(resolve(candidateDir));
                  }
                }
              }
            } catch {
              // Not critical — we'll still scan the root
            }
          }
        }
      }
    } catch {
      // Ignore parse errors
    }
  }

  return [...dirs];
}

// ---------------------------------------------------------------------------
// Core audit logic
// ---------------------------------------------------------------------------

function auditProject(projectDir, compromised) {
  const allDeps = [
    ...scanPackageJson(projectDir),
    ...scanPackageLockJson(projectDir),
    ...scanYarnLock(projectDir),
    ...scanPnpmLock(projectDir),
  ];

  const findings = [];
  const seen = new Set(); // Deduplicate

  for (const dep of allDeps) {
    const compromisedVersions = compromised.get(dep.name);
    if (!compromisedVersions) continue;
    if (!compromisedVersions.has(dep.version)) continue;

    const key = `${dep.name}@${dep.version}`;
    if (seen.has(key)) continue;
    seen.add(key);

    findings.push({
      name: dep.name,
      version: dep.version,
      source: dep.source,
      isDirect: dep.isDirect,
      compromisedVersions: [...compromisedVersions],
    });
  }

  return { projectDir, totalDepsScanned: allDeps.length, findings };
}

// ---------------------------------------------------------------------------
// Report formatting
// ---------------------------------------------------------------------------

function formatReport(results, meta) {
  const lines = [];
  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);
  const timestamp = new Date().toISOString();

  lines.push("═══════════════════════════════════════════════════════════════");
  lines.push("  npm Supply Chain Audit Report — Mini Shai-Hulud Campaign");
  lines.push("═══════════════════════════════════════════════════════════════");
  lines.push("");

  if (meta) {
    lines.push(`Advisory:     ${meta.advisory}`);
    lines.push(`Source:       ${meta.source}`);
    lines.push(`List updated: ${meta.last_updated}`);
  }
  lines.push(`Scan time:    ${timestamp}`);
  lines.push("");

  for (const result of results) {
    lines.push(`── ${result.projectDir}`);
    lines.push(`   Dependencies scanned: ${result.totalDepsScanned}`);

    if (result.findings.length === 0) {
      lines.push("   Status: ✅ CLEAN — no compromised packages found");
    } else {
      lines.push(`   Status: 🚨 AFFECTED — ${result.findings.length} compromised package(s) found`);
      lines.push("");
      for (const f of result.findings) {
        const directTag = f.isDirect ? " [DIRECT]" : " [TRANSITIVE]";
        lines.push(`   ⚠  ${f.name}@${f.version}${directTag}`);
        lines.push(`      Found in: ${f.source}`);
        lines.push(`      Known bad versions: ${f.compromisedVersions.join(", ")}`);
      }
    }
    lines.push("");
  }

  lines.push("───────────────────────────────────────────────────────────────");
  if (totalFindings > 0) {
    lines.push("RECOMMENDED ACTIONS:");
    lines.push("  1. Remove or downgrade affected packages immediately");
    lines.push("  2. Run `npm audit` for additional advisories");
    lines.push("  3. Rotate any npm, GitHub, and cloud tokens/credentials");
    lines.push("     that may have been exposed on this machine or in CI");
    lines.push("  4. Check CI/CD logs for unexpected network activity");
    lines.push("  5. Review the advisory for IOCs:");
    lines.push("     https://www.aikido.dev/blog/mini-shai-hulud-is-back-tanstack-compromised");
  } else {
    lines.push("No compromised packages detected. Stay vigilant — the");
    lines.push("advisory list is still growing. Re-run periodically.");
  }
  lines.push("───────────────────────────────────────────────────────────────");

  return lines.join("\n");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const args = parseArgs(process.argv);
  const projectDir = resolve(args.dir);

  if (!existsSync(projectDir)) {
    console.error(`Error: directory not found: ${projectDir}`);
    process.exit(2);
  }

  const { map: compromised, meta } = loadCompromisedPackages(args.packages);
  const projectDirs = discoverProjectDirs(projectDir);

  const results = projectDirs.map((dir) => auditProject(dir, compromised));
  const totalFindings = results.reduce((sum, r) => sum + r.findings.length, 0);

  if (args.json) {
    const output = {
      timestamp: new Date().toISOString(),
      advisory: meta,
      results: results.map((r) => ({
        ...r,
        status: r.findings.length > 0 ? "AFFECTED" : "CLEAN",
      })),
      summary: {
        projectsScanned: results.length,
        totalDepsScanned: results.reduce((s, r) => s + r.totalDepsScanned, 0),
        totalFindings,
      },
    };
    console.log(JSON.stringify(output, null, 2));
  } else {
    console.log(formatReport(results, meta));
  }

  if (args.ci && totalFindings > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Audit failed:", err.message);
  process.exit(2);
});
