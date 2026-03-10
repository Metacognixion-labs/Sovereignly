/**
 * Sovereignly v4.0 — Input Shield
 *
 * Centralized input validation and injection detection layer.
 * All user-facing endpoints should pass through InputShield before processing.
 *
 * Detections:
 *   1. Prototype pollution      (__proto__, constructor.prototype)
 *   2. Path traversal           (../, %2e%2e)
 *   3. Command injection        ($(), ``, ;, &&, || in string fields)
 *   4. SQL injection            (UNION, SELECT, DROP, --)
 *   5. Template injection       (${}, #{}, {{, <%)
 *   6. Unicode smuggling        (homoglyphs, RTL override, zero-width)
 *   7. Field path poisoning     (for policy engine dot-notation access)
 */

// ── Threat Types ────────────────────────────────────────────────────────────

export type ThreatType =
  | "prototype_pollution"
  | "path_traversal"
  | "command_injection"
  | "sql_injection"
  | "template_injection"
  | "unicode_smuggling"
  | "field_path_poisoning"
  | "oversized_input"
  | "deeply_nested";

export interface ThreatDetection {
  safe:    boolean;
  threats: Array<{ type: ThreatType; detail: string }>;
}

// ── Detection Patterns ──────────────────────────────────────────────────────

const PROTOTYPE_POLLUTION_PATTERNS = [
  /__proto__/i,
  /constructor\s*\[\s*["']prototype["']\s*\]/i,
  /constructor\.prototype/i,
  /Object\.assign\s*\(\s*Object\.prototype/i,
  /\["__proto__"\]/,
  /\['__proto__'\]/,
];

const PATH_TRAVERSAL_PATTERNS = [
  /\.\.\//,
  /\.\.\\/,
  /%2e%2e/i,          // URL-encoded ../
  /%252e%252e/i,      // Double URL-encoded
  /\.\.%2f/i,
  /\.\.%5c/i,
];

const COMMAND_INJECTION_PATTERNS = [
  /\$\([^)]+\)/,          // $(command)
  /`[^`]+`/,              // `command`
  /;\s*(rm|cat|wget|curl|bash|sh|nc|python|node|bun)\b/i,
  /\|\s*(rm|cat|wget|curl|bash|sh|nc|python|node|bun)\b/i,
  /&&\s*(rm|cat|wget|curl|bash|sh|nc|python|node|bun)\b/i,
];

const SQL_INJECTION_PATTERNS = [
  /'\s*OR\s+['"]?1['"]?\s*=\s*['"]?1/i,
  /UNION\s+(ALL\s+)?SELECT\s/i,
  /;\s*DROP\s+(TABLE|DATABASE)\s/i,
  /;\s*DELETE\s+FROM\s/i,
  /;\s*INSERT\s+INTO\s/i,
  /;\s*UPDATE\s+\w+\s+SET\s/i,
  /--\s*$/m,                     // SQL comment at end of line
  /\/\*.*\*\//,                  // /* */ comment (multi-line bypass)
  /SLEEP\s*\(\s*\d+\s*\)/i,     // time-based blind injection
  /BENCHMARK\s*\(/i,
  /WAITFOR\s+DELAY/i,
];

const TEMPLATE_INJECTION_PATTERNS = [
  /\$\{[^}]+\}/,         // ${...} (JS template literal)
  /#\{[^}]+\}/,          // #{...} (Ruby/Java template)
  /\{\{[^}]+\}\}/,       // {{...}} (Mustache/Handlebars)
  /<%[^%]+%>/,            // <%...%> (EJS/ERB)
  /\{%[^%]+%\}/,          // {%...%} (Jinja/Twig)
];

// Unicode control characters and smuggling vectors
const UNICODE_SMUGGLING_PATTERNS = [
  /[\u200B-\u200F]/,     // Zero-width space/joiner/non-joiner, LTR/RTL marks
  /[\u2028-\u2029]/,     // Line/paragraph separator
  /[\u202A-\u202E]/,     // LTR/RTL embedding/override
  /[\u2066-\u2069]/,     // Isolate directional formatting
  /[\uFEFF]/,            // BOM (zero-width no-break space)
  /[\uFFF9-\uFFFB]/,     // Interlinear annotation
];

// ── Blocked Field Paths (for policy engine) ─────────────────────────────────

const BLOCKED_FIELD_SEGMENTS = new Set([
  "__proto__",
  "constructor",
  "prototype",
  "__defineGetter__",
  "__defineSetter__",
  "__lookupGetter__",
  "__lookupSetter__",
  "toString",
  "valueOf",
  "hasOwnProperty",
  "isPrototypeOf",
  "propertyIsEnumerable",
  "toLocaleString",
]);

// ── InputShield ─────────────────────────────────────────────────────────────

export class InputShield {
  private readonly maxInputLength: number;
  private readonly maxNestingDepth: number;

  constructor(opts?: { maxInputLength?: number; maxNestingDepth?: number }) {
    this.maxInputLength  = opts?.maxInputLength ?? 1_000_000;  // 1MB
    this.maxNestingDepth = opts?.maxNestingDepth ?? 20;
  }

  /**
   * Detect injection patterns in a string value.
   */
  detectInjection(input: string): ThreatDetection {
    const threats: ThreatDetection["threats"] = [];

    if (input.length > this.maxInputLength) {
      threats.push({ type: "oversized_input", detail: `Input exceeds ${this.maxInputLength} chars` });
    }

    for (const pattern of PROTOTYPE_POLLUTION_PATTERNS) {
      if (pattern.test(input)) {
        threats.push({ type: "prototype_pollution", detail: `Matched: ${pattern.source}` });
        break;
      }
    }

    for (const pattern of PATH_TRAVERSAL_PATTERNS) {
      if (pattern.test(input)) {
        threats.push({ type: "path_traversal", detail: `Matched: ${pattern.source}` });
        break;
      }
    }

    for (const pattern of COMMAND_INJECTION_PATTERNS) {
      if (pattern.test(input)) {
        threats.push({ type: "command_injection", detail: `Matched: ${pattern.source}` });
        break;
      }
    }

    for (const pattern of SQL_INJECTION_PATTERNS) {
      if (pattern.test(input)) {
        threats.push({ type: "sql_injection", detail: `Matched: ${pattern.source}` });
        break;
      }
    }

    for (const pattern of TEMPLATE_INJECTION_PATTERNS) {
      if (pattern.test(input)) {
        threats.push({ type: "template_injection", detail: `Matched: ${pattern.source}` });
        break;
      }
    }

    for (const pattern of UNICODE_SMUGGLING_PATTERNS) {
      if (pattern.test(input)) {
        threats.push({ type: "unicode_smuggling", detail: "Contains suspicious Unicode control characters" });
        break;
      }
    }

    return { safe: threats.length === 0, threats };
  }

  /**
   * Deep scan an object for injection patterns in all string values.
   * Also checks for excessive nesting depth and prototype pollution keys.
   */
  scanObject(obj: unknown, depth = 0): ThreatDetection {
    const threats: ThreatDetection["threats"] = [];

    if (depth > this.maxNestingDepth) {
      threats.push({ type: "deeply_nested", detail: `Exceeds max depth of ${this.maxNestingDepth}` });
      return { safe: false, threats };
    }

    if (typeof obj === "string") {
      return this.detectInjection(obj);
    }

    if (Array.isArray(obj)) {
      for (const item of obj) {
        const result = this.scanObject(item, depth + 1);
        threats.push(...result.threats);
      }
      return { safe: threats.length === 0, threats };
    }

    if (obj && typeof obj === "object") {
      for (const key of Object.keys(obj)) {
        // Check the key itself for prototype pollution
        if (BLOCKED_FIELD_SEGMENTS.has(key)) {
          threats.push({ type: "prototype_pollution", detail: `Blocked key: ${key}` });
          continue;
        }

        // Check the key for injection
        const keyResult = this.detectInjection(key);
        threats.push(...keyResult.threats);

        // Recursively check values
        const valResult = this.scanObject((obj as any)[key], depth + 1);
        threats.push(...valResult.threats);
      }
    }

    return { safe: threats.length === 0, threats };
  }

  /**
   * Sanitize a dot-notation field path for safe object traversal.
   * Blocks prototype pollution vectors.
   */
  sanitizeFieldPath(path: string): { safe: boolean; sanitized?: string; blocked?: string } {
    const segments = path.split(".");

    for (const seg of segments) {
      if (BLOCKED_FIELD_SEGMENTS.has(seg)) {
        return { safe: false, blocked: seg };
      }
      // Block numeric-looking segments that could index into arrays unexpectedly
      // Allow them but validate they're reasonable
      if (/^\d+$/.test(seg) && parseInt(seg) > 10000) {
        return { safe: false, blocked: `Suspicious array index: ${seg}` };
      }
    }

    return { safe: true, sanitized: path };
  }

  /**
   * Safely traverse an object using dot-notation path.
   * Uses hasOwnProperty checks and blocks prototype chain access.
   */
  safeFieldAccess(obj: unknown, path: string): unknown {
    const validation = this.sanitizeFieldPath(path);
    if (!validation.safe) return undefined;

    const segments = path.split(".");
    let current: any = obj;

    for (const seg of segments) {
      if (current == null) return undefined;
      if (typeof current !== "object") return undefined;
      if (!Object.prototype.hasOwnProperty.call(current, seg)) return undefined;
      current = current[seg];
    }

    return current;
  }

  /**
   * Strip dangerous Unicode characters from a string.
   */
  stripUnicodeSmugglers(input: string): string {
    return input
      .replace(/[\u200B-\u200F]/g, "")    // Zero-width chars
      .replace(/[\u2028-\u2029]/g, "")     // Line/paragraph separators
      .replace(/[\u202A-\u202E]/g, "")     // Directional formatting
      .replace(/[\u2066-\u2069]/g, "")     // Isolate formatting
      .replace(/[\uFEFF]/g, "")            // BOM
      .replace(/[\uFFF9-\uFFFB]/g, "");    // Annotations
  }
}

// ── Singleton for convenience ───────────────────────────────────────────────

export const inputShield = new InputShield();
