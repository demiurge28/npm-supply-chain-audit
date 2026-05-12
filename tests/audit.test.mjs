import { describe, it } from "node:test";
import { strict as assert } from "node:assert";
import { execFileSync } from "node:child_process";
import { resolve, dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import {
  parseArgs,
  loadCompromisedPackages,
  scanPackageJson,
  scanPackageLockJson,
  scanYarnLock,
  scanPnpmLock,
  discoverProjectDirs,
  auditProject,
  formatReport,
  DEFAULT_PACKAGES_PATH,
} from "../scripts/audit.mjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(__dirname, "fixtures");
const AUDIT_SCRIPT = join(__dirname, "..", "scripts", "audit.mjs");

// Helper: build a compromised Map from a simple object
function makeCompromised(obj) {
  const map = new Map();
  for (const [name, versions] of Object.entries(obj)) {
    map.set(name, new Set(versions));
  }
  return map;
}

// ---------------------------------------------------------------------------
// parseArgs
// ---------------------------------------------------------------------------

describe("parseArgs", () => {
  it("returns defaults with no arguments", () => {
    const args = parseArgs(["node", "audit.mjs"]);
    assert.equal(args.dir, ".");
    assert.equal(args.json, false);
    assert.equal(args.ci, false);
    assert.equal(args.packages, DEFAULT_PACKAGES_PATH);
  });

  it("parses --dir", () => {
    const args = parseArgs(["node", "audit.mjs", "--dir", "/some/path"]);
    assert.equal(args.dir, "/some/path");
  });

  it("parses --json flag", () => {
    const args = parseArgs(["node", "audit.mjs", "--json"]);
    assert.equal(args.json, true);
  });

  it("parses --ci flag", () => {
    const args = parseArgs(["node", "audit.mjs", "--ci"]);
    assert.equal(args.ci, true);
  });

  it("parses --packages", () => {
    const args = parseArgs(["node", "audit.mjs", "--packages", "/custom.json"]);
    assert.equal(args.packages, "/custom.json");
  });

  it("parses multiple flags together", () => {
    const args = parseArgs([
      "node", "audit.mjs",
      "--dir", "/project",
      "--packages", "/list.json",
      "--json",
      "--ci",
    ]);
    assert.equal(args.dir, "/project");
    assert.equal(args.packages, "/list.json");
    assert.equal(args.json, true);
    assert.equal(args.ci, true);
  });
});

// ---------------------------------------------------------------------------
// loadCompromisedPackages
// ---------------------------------------------------------------------------

describe("loadCompromisedPackages", () => {
  it("loads the bundled compromised packages list", () => {
    const { map, meta } = loadCompromisedPackages(DEFAULT_PACKAGES_PATH);
    assert.ok(map instanceof Map);
    assert.ok(map.size > 100, `Expected >100 packages, got ${map.size}`);
    assert.ok(meta);
    assert.ok(meta.advisory);
    assert.ok(meta.source.includes("aikido.dev"));
  });

  it("loads a custom packages list with _meta", () => {
    const { map, meta } = loadCompromisedPackages(
      join(FIXTURES, "custom-packages.json")
    );
    assert.equal(map.size, 2);
    assert.ok(map.get("react").has("19.0.0"));
    assert.ok(map.get("lodash").has("4.17.21"));
    assert.equal(meta.advisory, "Test advisory");
  });

  it("loads a flat packages list (no _meta wrapper)", () => {
    const { map, meta } = loadCompromisedPackages(
      join(FIXTURES, "flat-packages.json")
    );
    assert.equal(map.size, 2);
    assert.ok(map.get("react").has("19.0.0"));
    assert.ok(map.get("express").has("4.18.2"));
    assert.equal(meta, null);
  });
});

// ---------------------------------------------------------------------------
// scanPackageJson
// ---------------------------------------------------------------------------

describe("scanPackageJson", () => {
  it("returns empty for directory with no package.json", () => {
    const results = scanPackageJson(join(FIXTURES, "empty-dir"));
    assert.deepEqual(results, []);
  });

  it("scans all dependency groups", () => {
    const results = scanPackageJson(join(FIXTURES, "clean-project"));
    assert.equal(results.length, 4); // 2 deps + 2 devDeps
    assert.ok(results.every((r) => r.isDirect === true));
    assert.ok(results.every((r) => r.source.startsWith("package.json")));
  });

  it("strips version prefixes (^, ~)", () => {
    const results = scanPackageJson(join(FIXTURES, "clean-project"));
    const react = results.find((r) => r.name === "react");
    assert.equal(react.version, "19.0.0"); // ^19.0.0 → 19.0.0
  });

  it("preserves exact versions", () => {
    const results = scanPackageJson(join(FIXTURES, "compromised-direct"));
    const router = results.find((r) => r.name === "@tanstack/react-router");
    assert.equal(router.version, "1.169.5");
  });

  it("correctly identifies dependency groups", () => {
    const results = scanPackageJson(join(FIXTURES, "compromised-direct"));
    const router = results.find((r) => r.name === "@tanstack/react-router");
    const mistral = results.find((r) => r.name === "@mistralai/mistralai");
    assert.ok(router.source.includes("dependencies"));
    assert.ok(mistral.source.includes("devDependencies"));
  });
});

// ---------------------------------------------------------------------------
// scanPackageLockJson
// ---------------------------------------------------------------------------

describe("scanPackageLockJson", () => {
  it("returns empty for directory with no lockfile", () => {
    const results = scanPackageLockJson(join(FIXTURES, "empty-dir"));
    assert.deepEqual(results, []);
  });

  it("parses lockfile v2 (packages key)", () => {
    const results = scanPackageLockJson(join(FIXTURES, "clean-project"));
    assert.ok(results.length > 0);
    assert.ok(results.every((r) => r.isDirect === false));
    assert.ok(results.every((r) => r.source === "package-lock.json"));
  });

  it("skips the root entry in lockfile v2", () => {
    const results = scanPackageLockJson(join(FIXTURES, "clean-project"));
    const root = results.find((r) => r.name === "clean-project");
    assert.equal(root, undefined);
  });

  it("extracts scoped package names from paths", () => {
    const results = scanPackageLockJson(
      join(FIXTURES, "compromised-transitive")
    );
    const tanstack = results.find(
      (r) => r.name === "@tanstack/router-core"
    );
    assert.ok(tanstack);
    assert.equal(tanstack.version, "1.169.8");
  });

  it("parses lockfile v1 (nested dependencies)", () => {
    const results = scanPackageLockJson(join(FIXTURES, "lockfile-v1"));
    assert.ok(results.length >= 3); // some-lib, cross-stitch, nested-safe, react
    const crossStitch = results.find((r) => r.name === "cross-stitch");
    assert.ok(crossStitch);
    assert.equal(crossStitch.version, "1.1.4");
  });

  it("walks deeply nested v1 dependencies", () => {
    const results = scanPackageLockJson(join(FIXTURES, "lockfile-v1"));
    const nested = results.find((r) => r.name === "nested-safe");
    assert.ok(nested);
    assert.equal(nested.version, "2.0.0");
  });

  it("parses lockfile v3", () => {
    const results = scanPackageLockJson(join(FIXTURES, "lockfile-v3"));
    assert.ok(results.length >= 3);
    const squawk = results.find((r) => r.name === "@squawk/mcp");
    assert.ok(squawk);
    assert.equal(squawk.version, "0.9.2");
  });
});

// ---------------------------------------------------------------------------
// scanYarnLock
// ---------------------------------------------------------------------------

describe("scanYarnLock", () => {
  it("returns empty for directory with no yarn.lock", () => {
    const results = scanYarnLock(join(FIXTURES, "empty-dir"));
    assert.deepEqual(results, []);
  });

  it("parses yarn v1 lockfile", () => {
    const results = scanYarnLock(join(FIXTURES, "yarn-v1"));
    assert.ok(results.length >= 2);
    const vue = results.find((r) => r.name === "@tanstack/vue-router");
    assert.ok(vue, "Should find @tanstack/vue-router");
    assert.equal(vue.version, "1.169.8");
    assert.equal(vue.source, "yarn.lock");
  });

  it("parses unscoped packages in yarn v1", () => {
    const results = scanYarnLock(join(FIXTURES, "yarn-v1"));
    const tsDna = results.find((r) => r.name === "ts-dna");
    assert.ok(tsDna, "Should find ts-dna");
    assert.equal(tsDna.version, "3.0.2");
  });

  it("parses yarn berry lockfile", () => {
    const results = scanYarnLock(join(FIXTURES, "yarn-berry"));
    const mistral = results.find((r) => r.name === "@mistralai/mistralai");
    assert.ok(mistral, "Should find @mistralai/mistralai in berry format");
    assert.equal(mistral.version, "2.2.4");
  });
});

// ---------------------------------------------------------------------------
// scanPnpmLock
// ---------------------------------------------------------------------------

describe("scanPnpmLock", () => {
  it("returns empty for directory with no pnpm-lock.yaml", () => {
    const results = scanPnpmLock(join(FIXTURES, "empty-dir"));
    assert.deepEqual(results, []);
  });

  it("parses pnpm v5 format (/@scope/name@version)", () => {
    const results = scanPnpmLock(join(FIXTURES, "pnpm-v5"));
    const beproduct = results.find(
      (r) => r.name === "@beproduct/nestjs-auth"
    );
    assert.ok(beproduct, "Should find @beproduct/nestjs-auth");
    assert.equal(beproduct.version, "0.1.5");
  });

  it("parses unscoped packages in pnpm v5", () => {
    const results = scanPnpmLock(join(FIXTURES, "pnpm-v5"));
    const gitBranch = results.find(
      (r) => r.name === "git-branch-selector"
    );
    assert.ok(gitBranch, "Should find git-branch-selector");
    assert.equal(gitBranch.version, "1.3.4");
  });

  it("parses pnpm v6+ format (name@version with quotes)", () => {
    const results = scanPnpmLock(join(FIXTURES, "pnpm-v6"));
    const taskflow = results.find(
      (r) => r.name === "@taskflow-corp/cli"
    );
    assert.ok(taskflow, "Should find @taskflow-corp/cli");
    assert.equal(taskflow.version, "0.1.26");
  });

  it("parses unscoped packages in pnpm v6+", () => {
    const results = scanPnpmLock(join(FIXTURES, "pnpm-v6"));
    const agent = results.find((r) => r.name === "agentwork-cli");
    assert.ok(agent, "Should find agentwork-cli");
    assert.equal(agent.version, "0.1.5");
  });
});

// ---------------------------------------------------------------------------
// discoverProjectDirs
// ---------------------------------------------------------------------------

describe("discoverProjectDirs", () => {
  it("always includes the root directory", () => {
    const dirs = discoverProjectDirs(join(FIXTURES, "clean-project"));
    assert.equal(dirs.length, 1);
    assert.ok(dirs[0].endsWith("clean-project"));
  });

  it("returns root for empty directory", () => {
    const dirs = discoverProjectDirs(join(FIXTURES, "empty-dir"));
    assert.equal(dirs.length, 1);
  });

  it("discovers monorepo workspace packages", () => {
    const dirs = discoverProjectDirs(join(FIXTURES, "monorepo"));
    // root + app-a + app-b = 3 (lib-no-pkg has no package.json)
    assert.equal(dirs.length, 3);
    assert.ok(dirs.some((d) => d.endsWith("app-a")));
    assert.ok(dirs.some((d) => d.endsWith("app-b")));
  });

  it("skips workspace subdirs without package.json", () => {
    const dirs = discoverProjectDirs(join(FIXTURES, "monorepo"));
    assert.ok(!dirs.some((d) => d.endsWith("lib-no-pkg")));
  });
});

// ---------------------------------------------------------------------------
// auditProject
// ---------------------------------------------------------------------------

describe("auditProject", () => {
  const compromised = makeCompromised({
    "@tanstack/react-router": ["1.169.5", "1.169.8"],
    "@tanstack/router-core": ["1.169.5", "1.169.8"],
    "@tanstack/history": ["1.161.9", "1.161.12"],
    "@mistralai/mistralai": ["2.2.2", "2.2.3", "2.2.4"],
    "safe-action": ["0.8.3", "0.8.4"],
    "cross-stitch": ["1.1.3", "1.1.4", "1.1.5", "1.1.6"],
    "@squawk/mcp": ["0.9.1", "0.9.2", "0.9.3", "0.9.4"],
    "@uipath/cli": ["1.0.1"],
    "ts-dna": ["3.0.1", "3.0.2", "3.0.3", "3.0.4"],
    "@tanstack/vue-router": ["1.169.5", "1.169.8"],
    "@beproduct/nestjs-auth": ["0.1.2", "0.1.3", "0.1.4", "0.1.5"],
    "git-branch-selector": ["1.3.3", "1.3.4", "1.3.5"],
    "@taskflow-corp/cli": ["0.1.24", "0.1.25", "0.1.26"],
    "agentwork-cli": ["0.1.4", "0.1.5"],
  });

  it("reports clean project with zero findings", () => {
    const result = auditProject(join(FIXTURES, "clean-project"), compromised);
    assert.equal(result.findings.length, 0);
    assert.ok(result.totalDepsScanned > 0);
  });

  it("detects compromised direct dependencies", () => {
    const result = auditProject(
      join(FIXTURES, "compromised-direct"),
      compromised
    );
    assert.ok(result.findings.length >= 2);
    const router = result.findings.find(
      (f) => f.name === "@tanstack/react-router"
    );
    assert.ok(router);
    assert.equal(router.isDirect, true);
    assert.equal(router.version, "1.169.5");
  });

  it("detects compromised transitive dependencies", () => {
    const result = auditProject(
      join(FIXTURES, "compromised-transitive"),
      compromised
    );
    assert.ok(result.findings.length >= 2);
    const routerCore = result.findings.find(
      (f) => f.name === "@tanstack/router-core"
    );
    assert.ok(routerCore);
    assert.equal(routerCore.isDirect, false);
  });

  it("deduplicates findings across package.json and lockfile", () => {
    const result = auditProject(
      join(FIXTURES, "mixed-findings"),
      compromised
    );
    // @tanstack/react-router@1.169.5 appears in both package.json and lockfile
    const routerFindings = result.findings.filter(
      (f) => f.name === "@tanstack/react-router"
    );
    assert.equal(routerFindings.length, 1, "Should deduplicate same package@version");
  });

  it("reports findings from different sources correctly", () => {
    const result = auditProject(
      join(FIXTURES, "mixed-findings"),
      compromised
    );
    // Should find: @tanstack/react-router, safe-action, @tanstack/router-core
    assert.ok(result.findings.length >= 3);
  });

  it("returns empty findings for empty directory", () => {
    const result = auditProject(join(FIXTURES, "empty-dir"), compromised);
    assert.equal(result.findings.length, 0);
    assert.equal(result.totalDepsScanned, 0);
  });

  it("includes compromisedVersions array in each finding", () => {
    const result = auditProject(
      join(FIXTURES, "compromised-direct"),
      compromised
    );
    for (const finding of result.findings) {
      assert.ok(Array.isArray(finding.compromisedVersions));
      assert.ok(finding.compromisedVersions.length > 0);
    }
  });

  it("detects findings in lockfile v1 nested deps", () => {
    const result = auditProject(join(FIXTURES, "lockfile-v1"), compromised);
    const cs = result.findings.find((f) => f.name === "cross-stitch");
    assert.ok(cs, "Should detect cross-stitch in nested v1 deps");
    assert.equal(cs.version, "1.1.4");
  });

  it("detects findings in lockfile v3", () => {
    const result = auditProject(join(FIXTURES, "lockfile-v3"), compromised);
    assert.ok(result.findings.length >= 2);
    assert.ok(result.findings.some((f) => f.name === "@squawk/mcp"));
    assert.ok(result.findings.some((f) => f.name === "@uipath/cli"));
  });

  it("detects findings in yarn v1 lockfile", () => {
    const result = auditProject(join(FIXTURES, "yarn-v1"), compromised);
    assert.ok(result.findings.some((f) => f.name === "@tanstack/vue-router"));
    assert.ok(result.findings.some((f) => f.name === "ts-dna"));
  });

  it("detects findings in yarn berry lockfile", () => {
    const result = auditProject(join(FIXTURES, "yarn-berry"), compromised);
    assert.ok(
      result.findings.some((f) => f.name === "@mistralai/mistralai")
    );
  });

  it("detects findings in pnpm v5 lockfile", () => {
    const result = auditProject(join(FIXTURES, "pnpm-v5"), compromised);
    assert.ok(
      result.findings.some((f) => f.name === "@beproduct/nestjs-auth")
    );
    assert.ok(
      result.findings.some((f) => f.name === "git-branch-selector")
    );
  });

  it("detects findings in pnpm v6+ lockfile", () => {
    const result = auditProject(join(FIXTURES, "pnpm-v6"), compromised);
    assert.ok(
      result.findings.some((f) => f.name === "@taskflow-corp/cli")
    );
    assert.ok(
      result.findings.some((f) => f.name === "agentwork-cli")
    );
  });
});

// ---------------------------------------------------------------------------
// formatReport
// ---------------------------------------------------------------------------

describe("formatReport", () => {
  it("includes CLEAN status for clean results", () => {
    const report = formatReport(
      [{ projectDir: "/test", totalDepsScanned: 10, findings: [] }],
      null
    );
    assert.ok(report.includes("CLEAN"));
    assert.ok(report.includes("No compromised packages detected"));
  });

  it("includes AFFECTED status and findings details", () => {
    const report = formatReport(
      [
        {
          projectDir: "/test",
          totalDepsScanned: 10,
          findings: [
            {
              name: "@tanstack/react-router",
              version: "1.169.5",
              source: "package.json (dependencies)",
              isDirect: true,
              compromisedVersions: ["1.169.5", "1.169.8"],
            },
          ],
        },
      ],
      null
    );
    assert.ok(report.includes("AFFECTED"));
    assert.ok(report.includes("@tanstack/react-router@1.169.5"));
    assert.ok(report.includes("[DIRECT]"));
    assert.ok(report.includes("RECOMMENDED ACTIONS"));
  });

  it("includes [TRANSITIVE] tag for non-direct deps", () => {
    const report = formatReport(
      [
        {
          projectDir: "/test",
          totalDepsScanned: 5,
          findings: [
            {
              name: "safe-action",
              version: "0.8.3",
              source: "package-lock.json",
              isDirect: false,
              compromisedVersions: ["0.8.3", "0.8.4"],
            },
          ],
        },
      ],
      null
    );
    assert.ok(report.includes("[TRANSITIVE]"));
  });

  it("includes advisory metadata when provided", () => {
    const meta = {
      advisory: "Test Advisory",
      source: "https://example.com",
      last_updated: "2026-05-12",
    };
    const report = formatReport(
      [{ projectDir: "/test", totalDepsScanned: 0, findings: [] }],
      meta
    );
    assert.ok(report.includes("Test Advisory"));
    assert.ok(report.includes("https://example.com"));
    assert.ok(report.includes("2026-05-12"));
  });

  it("includes scan time", () => {
    const report = formatReport(
      [{ projectDir: "/test", totalDepsScanned: 0, findings: [] }],
      null
    );
    assert.ok(report.includes("Scan time:"));
  });
});

// ---------------------------------------------------------------------------
// CLI integration tests (run as subprocess)
// ---------------------------------------------------------------------------

describe("CLI integration", () => {
  function runAudit(args) {
    try {
      const stdout = execFileSync("node", [AUDIT_SCRIPT, ...args], {
        encoding: "utf-8",
        timeout: 10000,
      });
      return { stdout, exitCode: 0 };
    } catch (err) {
      return { stdout: err.stdout ?? "", stderr: err.stderr ?? "", exitCode: err.status };
    }
  }

  it("exits 0 for clean project", () => {
    const { exitCode } = runAudit([
      "--dir", join(FIXTURES, "clean-project"),
    ]);
    assert.equal(exitCode, 0);
  });

  it("exits 0 for compromised project without --ci", () => {
    const { exitCode } = runAudit([
      "--dir", join(FIXTURES, "compromised-direct"),
    ]);
    assert.equal(exitCode, 0);
  });

  it("exits 1 for compromised project with --ci", () => {
    const { exitCode } = runAudit([
      "--dir", join(FIXTURES, "compromised-direct"),
      "--ci",
    ]);
    assert.equal(exitCode, 1);
  });

  it("exits 0 for clean project with --ci", () => {
    const { exitCode } = runAudit([
      "--dir", join(FIXTURES, "clean-project"),
      "--ci",
    ]);
    assert.equal(exitCode, 0);
  });

  it("outputs valid JSON with --json", () => {
    const { stdout, exitCode } = runAudit([
      "--dir", join(FIXTURES, "compromised-transitive"),
      "--json",
    ]);
    assert.equal(exitCode, 0);
    const parsed = JSON.parse(stdout);
    assert.ok(parsed.timestamp);
    assert.ok(parsed.results);
    assert.ok(parsed.summary);
    assert.equal(parsed.summary.projectsScanned, 1);
    assert.ok(parsed.summary.totalFindings > 0);
  });

  it("JSON output includes AFFECTED status", () => {
    const { stdout } = runAudit([
      "--dir", join(FIXTURES, "compromised-direct"),
      "--json",
    ]);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.results[0].status, "AFFECTED");
  });

  it("JSON output includes CLEAN status", () => {
    const { stdout } = runAudit([
      "--dir", join(FIXTURES, "clean-project"),
      "--json",
    ]);
    const parsed = JSON.parse(stdout);
    assert.equal(parsed.results[0].status, "CLEAN");
  });

  it("accepts custom --packages list", () => {
    const { stdout } = runAudit([
      "--dir", join(FIXTURES, "clean-project"),
      "--packages", join(FIXTURES, "custom-packages.json"),
      "--json",
    ]);
    const parsed = JSON.parse(stdout);
    // clean-project has react@19.0.0 which is "compromised" in custom list
    assert.ok(parsed.summary.totalFindings > 0);
    assert.equal(parsed.advisory.advisory, "Test advisory");
  });

  it("exits 2 for nonexistent directory", () => {
    const { exitCode } = runAudit([
      "--dir", "/nonexistent/path/xyz",
    ]);
    assert.equal(exitCode, 2);
  });

  it("human-readable output contains report header", () => {
    const { stdout } = runAudit([
      "--dir", join(FIXTURES, "clean-project"),
    ]);
    assert.ok(stdout.includes("npm Supply Chain Audit Report"));
  });

  it("--json and --ci together: exits 1 with valid JSON", () => {
    const { stdout, exitCode } = runAudit([
      "--dir", join(FIXTURES, "compromised-direct"),
      "--json",
      "--ci",
    ]);
    assert.equal(exitCode, 1);
    const parsed = JSON.parse(stdout);
    assert.ok(parsed.summary.totalFindings > 0);
  });

  it("scans monorepo workspaces", () => {
    const { stdout } = runAudit([
      "--dir", join(FIXTURES, "monorepo"),
      "--json",
    ]);
    const parsed = JSON.parse(stdout);
    // root + app-a + app-b
    assert.equal(parsed.summary.projectsScanned, 3);
  });

  it("detects compromised package in monorepo workspace", () => {
    const { stdout } = runAudit([
      "--dir", join(FIXTURES, "monorepo"),
      "--json",
    ]);
    const parsed = JSON.parse(stdout);
    const appB = parsed.results.find((r) => r.projectDir.endsWith("app-b"));
    assert.ok(appB, "Should have results for app-b");
    assert.equal(appB.status, "AFFECTED");
    assert.ok(appB.findings.some((f) => f.name === "@tanstack/react-router"));
  });
});
