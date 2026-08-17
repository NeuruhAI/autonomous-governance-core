import fs from "node:fs";
import path from "node:path";
import { targetPathErrors } from "./canonical.mjs";

// Path scope enforcement for risk-scoped authorization. Three layers, each
// fail-closed:
//   1. Lexical canonical form (one spelling per path, no traversal, no
//      wildcards) — reuses the ratified target-path rules.
//   2. Real-path resolution — the deepest existing ancestor is resolved
//      through the filesystem so a symlink inside an approved root can never
//      smuggle a write outside it.
//   3. Sensitivity classes — secret material roots and canonical Governance
//      state are recognized by content, and NO grant or approval evaluated in
//      this module's callers may admit them.

export const PATH_SENSITIVITY = ["normal", "secret", "governance_canonical"];

// Roots that are categorically too broad to ever appear as a grant root.
// A founder proof directory under Desktop is grantable; Desktop itself is not.
const SYSTEM_FORBIDDEN_TOP_SEGMENTS = new Set([
  "etc",
  "bin",
  "sbin",
  "usr",
  "System",
  "Library",
  "boot",
  "dev",
  "proc",
  "sys"
]);

const HOME_TOP_SEGMENTS = new Set(["Users", "home"]);

export function pathLexicalErrors(pathValue) {
  const errors = targetPathErrors(pathValue);

  if (typeof pathValue === "string" && pathValue.includes("*")) {
    errors.push("path must not contain wildcards.");
  }

  if (typeof pathValue === "string" && pathValue.startsWith("~")) {
    errors.push("path must be absolute, not home-relative.");
  }

  return errors;
}

export function pathSegments(pathValue) {
  return pathValue.split("/").filter(Boolean);
}

// Segment-safe containment: "/root-evil" is never within "/root".
export function isWithinRoot(childPath, rootPath) {
  if (typeof childPath !== "string" || typeof rootPath !== "string") return false;
  if (childPath === rootPath) return true;
  return childPath.startsWith(rootPath.endsWith("/") ? rootPath : rootPath + "/");
}

// Returns a reason string when a root is too broad to grant, else null.
export function broadRootError(rootPath) {
  const segments = pathSegments(rootPath);

  if (segments.length === 0) {
    return "the filesystem root is never grantable.";
  }

  if (SYSTEM_FORBIDDEN_TOP_SEGMENTS.has(segments[0])) {
    return "system roots are never grantable: /" + segments[0];
  }

  if (HOME_TOP_SEGMENTS.has(segments[0])) {
    // /Users, /Users/<user>, and /Users/<user>/<Desktop|Documents|…> are all
    // whole-life scopes. A grantable home root names a specific directory one
    // level deeper (e.g. /Users/x/Desktop/NEURUH_LIVE_PROOF_20260816).
    if (segments.length < 4) {
      return "home-level directories are too broad to grant; name a specific subdirectory.";
    }
    return null;
  }

  if (segments.length < 3) {
    return "root is too broad to grant; name a specific directory at least three segments deep.";
  }

  return null;
}

// Secret-denied roots: recognized by content of the path itself, checked on
// both the lexical and the resolved spelling. Nothing evaluated downstream —
// grant, session scope, or presented approval — may admit these.
const SECRET_SEGMENTS = new Set([".ssh", ".gnupg", ".aws", ".kube", "secrets"]);

const SECRET_BASENAME_PATTERNS = [
  /^id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/,
  /\.pem$/,
  /\.key$/,
  /\.p12$/,
  /\.pfx$/,
  /^credentials$/,
  /^\.netrc$/,
  /^\.env$/,
  /^\.env\.(?!example$|sample$|template$).+$/,
  /keychain/i,
  /\.secret$/
];

// Canonical Governance state: policy source, trust configuration and the
// runtime ledgers of this repository. Writes here are constitutional changes,
// not operations, and always require the founder interactively.
const GOVERNANCE_REPO_SEGMENT = "autonomous-governance-core";
const GOVERNANCE_PROTECTED_CHILD_SEGMENTS = new Set(["config", "src", ".p2b-runtime"]);

export function classifyPathSensitivity(pathValue) {
  const segments = pathSegments(pathValue);
  const basename = segments.length ? segments[segments.length - 1] : "";

  for (const segment of segments) {
    if (SECRET_SEGMENTS.has(segment)) {
      return { sensitivity: "secret", detail: "path traverses secret-denied segment: " + segment };
    }
  }

  for (const pattern of SECRET_BASENAME_PATTERNS) {
    if (pattern.test(basename)) {
      return { sensitivity: "secret", detail: "path names secret material: " + basename };
    }
  }

  const governanceIndex = segments.indexOf(GOVERNANCE_REPO_SEGMENT);

  if (governanceIndex >= 0 && governanceIndex + 1 < segments.length && GOVERNANCE_PROTECTED_CHILD_SEGMENTS.has(segments[governanceIndex + 1])) {
    return {
      sensitivity: "governance_canonical",
      detail: "path targets canonical Governance state: " + segments.slice(governanceIndex, governanceIndex + 2).join("/")
    };
  }

  return { sensitivity: "normal", detail: null };
}

// Resolve a lexically-canonical absolute path through the real filesystem:
// the deepest existing ancestor is realpath'd (following symlinks), the
// not-yet-existing remainder is appended lexically. A path on a host where
// nothing exists resolves to itself.
export function resolveRealTargetPath(pathValue, fsImpl = fs) {
  let existing = pathValue;
  const remainder = [];

  while (existing !== "/" && !fsImpl.existsSync(existing)) {
    remainder.unshift(path.basename(existing));
    existing = path.dirname(existing);
  }

  let resolvedBase;

  try {
    resolvedBase = fsImpl.existsSync(existing) ? fsImpl.realpathSync(existing) : existing;
  } catch (error) {
    return { ok: false, error: "real path resolution failed: " + error.message };
  }

  const resolved = remainder.length ? path.join(resolvedBase, ...remainder) : resolvedBase;
  return { ok: true, resolved };
}

// Real containment: both sides resolved, then segment-safe containment. Any
// resolution failure or escape is an error list (empty list = contained).
export function realContainmentErrors(targetPath, rootPath, fsImpl = fs) {
  const resolvedTarget = resolveRealTargetPath(targetPath, fsImpl);

  if (!resolvedTarget.ok) return [resolvedTarget.error];

  const resolvedRoot = resolveRealTargetPath(rootPath, fsImpl);

  if (!resolvedRoot.ok) return [resolvedRoot.error];

  if (!isWithinRoot(targetPath, rootPath)) {
    return ["path is outside the granted root."];
  }

  if (!isWithinRoot(resolvedTarget.resolved, resolvedRoot.resolved)) {
    return [
      "symlink escape: path resolves outside the granted root (" +
        targetPath +
        " -> " +
        resolvedTarget.resolved +
        ")."
    ];
  }

  return [];
}
