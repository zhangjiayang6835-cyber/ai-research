/**
 * security/crlf-injection-fix.js
 *
 * Fix for Issue #1139: [BUG] CRLF Injection in Access Log → HTTP Response Splitting
 * Bounty: $120 | Severity: Medium
 *
 * Vulnerability:
 *   The access-log middleware wrote the raw User-Agent header directly into an
 *   HTTP response header:
 *       res.setHeader("X-Log", userAgent);
 *   An attacker can inject CRLF sequences (\r\n) into the User-Agent value
 *   to split the HTTP response and inject arbitrary headers or body content.
 *
 *   Malicious User-Agent example:
 *       Mozilla/5.0\r\nX-Hacked: true\r\n\r\n<script>alert(1)</script>
 *
 * Fix strategy (defense in depth):
 *   1. Strip / reject any CRLF characters (\r, \n) from user-controlled input.
 *   2. Never write raw user input into response headers (or into any header at all).
 *   3. When user data MUST appear in a header, encode it with encodeURIComponent()
 *      so control characters are percent-encoded and cannot break the HTTP parsing.
 *
 * ─────────────────────────────────────────────────────────────────────
 * PART 1 — Vulnerable code (for reference / testing)
 * ─────────────────────────────────────────────────────────────────────
 *
 *   app.use((req, res, next) => {
 *     const userAgent = req.headers['user-agent'] || 'unknown';
 *
 *     // 🔴 VULNERABLE — raw user input written directly into a response header
 *     res.setHeader("X-Log", userAgent);
 *
 *     console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} :: ${userAgent}`);
 *     next();
 *   });
 *
 *   If User-Agent = "Mozilla/5.0\r\nX-Hacked: true\r\n\r\n<html>..."
 *   the server will emit:
 *       HTTP/1.1 200 OK
 *       X-Log: Mozilla/5.0
 *       X-Hacked: true
 *
 *       <html>...
 *   which is a classic HTTP Response Splitting / CRLF injection.
 *
 * ─────────────────────────────────────────────────────────────────────
 * PART 2 — Security-hardened middleware
 * ─────────────────────────────────────────────────────────────────────
 */

"use strict";

const { URLSearchParams } = require("url");

// ---------------------------------------------------------------------------
// Helper: strip all CRLF / control characters from a string
// ---------------------------------------------------------------------------

/**
 * Remove \r and \n from a value.  Also trims leading/trailing whitespace
 * and collapses internal runs of spaces for readability in logs.
 *
 * @param {string} input
 * @returns {string}
 */
function sanitizeForLog(input) {
  if (typeof input !== "string") return String(input ?? "unknown");

  // Reject / strip CRLF and other dangerous control chars
  const cleaned = input
    .replace(/\r/g, "")   // carriage return
    .replace(/\n/g, "")   // line feed
    .replace(/\x00/g, "") // null byte
    .trim();

  return cleaned.length > 0 ? cleaned : "unknown";
}

// ---------------------------------------------------------------------------
// Helper: encode user data for safe inclusion in response headers
// ---------------------------------------------------------------------------

/**
 * Safely embed a string value into an HTTP header.
 *
 *   1. Sanitises CRLF first (belt-and-suspenders even though we never use
 *      raw user input in headers any more).
 *   2. Applies encodeURIComponent so every byte is percent-encoded.
 *
 * @param {string} value
 * @returns {string} percent-encoded header value
 */
function safeHeaderValue(value) {
  return encodeURIComponent(sanitizeForLog(value));
}

// ---------------------------------------------------------------------------
// Fixed middleware: structured logging WITHOUT writing user input to headers
// ---------------------------------------------------------------------------

/**
 * Replace the vulnerable `res.setHeader("X-Log", userAgent)` pattern with
 * a secure middleware that:
 *   • Sanitises the User-Agent (removes CRLF / control characters).
 *   • Does NOT write the (sanitised or raw) User-Agent to any response header.
 *   • Writes a structured log line to stdout / your log sink instead.
 *
 *   If an upstream system absolutely requires a header, use safeHeaderValue()
 *   which percent-encodes everything.
 */
function accessLogMiddleware(req, res, next) {
  // ── 1. Sanitise user input ──────────────────────────────────────────────
  const userAgent = sanitizeForLog(req.headers["user-agent"] || "unknown");
  const clientIp = sanitizeForLog(req.headers["x-forwarded-for"] ?? req.ip ?? "unknown");

  // ── 2. Reject requests whose User-Agent contained CRLF ──────────────────
  const rawUserAgent = req.headers["user-agent"] || "";
  if (/\r|\n/.test(rawUserAgent)) {
    // Log the suspicious request for monitoring / alerting
    console.warn(
      `[SECURITY] CRLF detected in User-Agent from ${clientIp}: ${rawUserAgent.replace(/\r/g, "\\r").replace(/\n/g, "\\n")}`
    );
    // Reject with 400 — do not process requests containing injection attempts
    if (!res.headersSent) {
      return res.status(400).json({
        error: "Bad Request",
        message: "Invalid characters detected in request headers",
      });
    }
  }

  // ── 3. Log to stdout (structured, NOT in response headers) ─────────────
  const timestamp = new Date().toISOString();
  const logLine = `[${timestamp}] ${req.method} ${req.path} :: UA=${userAgent} :: IP=${clientIp}`;
  console.log(logLine);

  // ── 4. Optional: set a header with safe, opaque trace id ───────────────
  //     We do NOT include any user input in the header.  If an encoder is
  //     required for compatibility, use safeHeaderValue() on the sanitised
  //     value (belt-and-suspenders):
  //
  //     res.setHeader("X-Log-UA", safeHeaderValue(userAgent));
  //
  //     However the recommendation is to omit this header entirely and use
  //     a random trace id instead:
  const traceId = crypto.randomUUID?.() ?? `t-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  res.setHeader("X-Request-Id", traceId); // safe, no user input

  return next();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

function runTests() {
  const tests = [
    {
      name: "sanitizeForLog strips CRLF",
      input: "Mozilla/5.0\r\nFirefox",
      expected: "Mozilla/5.0Firefox",
    },
    {
      name: "sanitizeForLog strips LF",
      input: "curl/7.68\nX-Injected: evil",
      expected: "curl/7.68X-Injected: evil",
    },
    {
      name: "sanitizeForLog strips null bytes",
      input: "bot\x00probe",
      expected: "botprobe",
    },
    {
      name: "safeHeaderValue percent-encodes slashes and colons",
      input: "Mozilla/5.0 (X11; Linux)",
      expected: "Mozilla%2F5.0%20(X11%3B%20Linux)",
    },
    {
      name: "safeHeaderValue handles CRLF injection payload",
      input: "Mozilla/5.0\r\nX-Hacked: true\r\n\r\n<script>",
      expected: "Mozilla%2F5.0X-Hacked%3A%20true%3Cscript%3E",
    },
  ];

  let passed = 0;
  let failed = 0;

  for (const t of tests) {
    let result;
    if (t.name.startsWith("sanitizeForLog")) {
      result = sanitizeForLog(t.input);
    } else {
      result = safeHeaderValue(t.input);
    }

    if (result === t.expected) {
      console.log(`  ✅ ${t.name}`);
      passed++;
    } else {
      console.log(`  ❌ ${t.name}`);
      console.log(`     expected: ${t.expected}`);
      console.log(`     got:      ${result}`);
      failed++;
    }
  }

  console.log(`\nResults: ${passed}/${tests.length} passed`);
  if (failed > 0) process.exit(1);
}

// Run tests when executed directly
if (require.main === module) {
  console.log("Running CRLF injection fix tests...\n");
  runTests();
}

module.exports = {
  accessLogMiddleware,
  sanitizeForLog,
  safeHeaderValue,
  runTests,
};
