import crypto from "node:crypto";

// Deterministic canonical JSON for hashing decision content.
// Ambiguous values are REJECTED, never silently normalized: two byte-different
// inputs must never canonicalize to the same string, and one logical value must
// never canonicalize two ways.

const MAX_DEPTH = 64;

export class CanonicalizationError extends Error {
  constructor(message, path) {
    super(message + (path ? " (at " + path + ")" : ""));
    this.name = "CanonicalizationError";
    this.canonical_path = path || "$";
  }
}

function assertCanonicalString(value, path) {
  if (typeof value.isWellFormed === "function" && !value.isWellFormed()) {
    throw new CanonicalizationError("String contains lone surrogates.", path);
  }

  if (value.normalize("NFC") !== value) {
    throw new CanonicalizationError("String is not Unicode NFC normalized.", path);
  }

  if (value.includes("\u0000")) {
    throw new CanonicalizationError("String contains NUL.", path);
  }
}

function canonicalizeValue(value, path, depth) {
  if (depth > MAX_DEPTH) {
    throw new CanonicalizationError("Nesting exceeds canonical depth limit.", path);
  }

  if (value === null) return "null";

  const kind = typeof value;

  if (kind === "boolean") return value ? "true" : "false";

  if (kind === "number") {
    if (!Number.isFinite(value)) {
      throw new CanonicalizationError("Non-finite number.", path);
    }
    if (Object.is(value, -0)) {
      throw new CanonicalizationError("Negative zero is ambiguous.", path);
    }
    if (Number.isInteger(value) && !Number.isSafeInteger(value)) {
      throw new CanonicalizationError("Integer outside safe range.", path);
    }
    return JSON.stringify(value);
  }

  if (kind === "string") {
    assertCanonicalString(value, path);
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    const parts = value.map((item, index) => {
      if (item === undefined) {
        throw new CanonicalizationError("Array holds undefined.", path + "[" + index + "]");
      }
      return canonicalizeValue(item, path + "[" + index + "]", depth + 1);
    });
    return "[" + parts.join(",") + "]";
  }

  if (kind === "object") {
    const proto = Object.getPrototypeOf(value);

    if (proto !== Object.prototype && proto !== null) {
      throw new CanonicalizationError("Only plain objects are canonical.", path);
    }

    const keys = Object.keys(value).sort();
    const seen = new Set();
    const parts = [];

    for (const key of keys) {
      assertCanonicalString(key, path + "." + key);

      if (key === "__proto__" || key === "constructor" || key === "prototype") {
        throw new CanonicalizationError("Forbidden object key: " + key, path);
      }

      const folded = key.normalize("NFC");

      if (seen.has(folded)) {
        throw new CanonicalizationError("Duplicate key after normalization: " + key, path);
      }

      seen.add(folded);

      const item = value[key];

      if (item === undefined) {
        throw new CanonicalizationError("Object holds undefined value.", path + "." + key);
      }

      parts.push(JSON.stringify(key) + ":" + canonicalizeValue(item, path + "." + key, depth + 1));
    }

    return "{" + parts.join(",") + "}";
  }

  throw new CanonicalizationError("Value type is not canonical: " + kind, path);
}

export function canonicalize(value) {
  if (value === undefined) {
    throw new CanonicalizationError("undefined is not canonical.", "$");
  }

  return canonicalizeValue(value, "$", 0);
}

export function sha256Hex(text) {
  return crypto.createHash("sha256").update(text, "utf8").digest("hex");
}

export function hashCanonical(value) {
  return sha256Hex(canonicalize(value));
}

export function hmacHex(secret, text) {
  return crypto.createHmac("sha256", secret).update(text, "utf8").digest("hex");
}

export function timingSafeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length || a.length === 0) {
    return false;
  }

  return crypto.timingSafeEqual(Buffer.from(a, "utf8"), Buffer.from(b, "utf8"));
}

export function isSha256Hex(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

// Target-path ambiguity rules: an approval binds an exact target, so any path
// spelling that could alias another spelling is rejected outright.
export function targetPathErrors(pathValue) {
  const errors = [];

  if (typeof pathValue !== "string" || pathValue.length === 0) {
    return ["target path must be a non-empty string."];
  }

  try {
    assertCanonicalString(pathValue, "target.id");
  } catch (error) {
    return [error.message];
  }

  if (!pathValue.startsWith("/")) errors.push("target path must be absolute.");
  if (pathValue.includes("\\")) errors.push("target path must not contain backslashes.");
  if (pathValue.includes("//")) errors.push("target path must not contain empty segments.");
  if (pathValue !== "/" && pathValue.endsWith("/")) errors.push("target path must not end with a slash.");

  const segments = pathValue.split("/");

  if (segments.includes(".") || segments.includes("..")) {
    errors.push("target path must not contain . or .. segments.");
  }

  return errors;
}
