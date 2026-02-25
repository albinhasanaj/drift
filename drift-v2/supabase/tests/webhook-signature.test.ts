/**
 * Phase E: Webhook Signature + URL Validation tests
 * Covers: CT0-E-02 (signature verification), CT0-E-07 (URL validation — unit level)
 *
 * These are pure unit tests — no Supabase required.
 */

import {
  assertEquals,
  assert,
} from "https://deno.land/std@0.208.0/assert/mod.ts";

import {
  signWebhookPayload,
  verifyWebhookSignature,
  computeHmac,
  parseSignatureHeader,
  sha256Hash,
  generateWebhookSecret,
} from "../functions/shared/webhook-signature.ts";

import { validateWebhookUrl } from "../functions/shared/url-validator.ts";

// ── CT0-E-02: HMAC signature verification ──

Deno.test("CT0-E-02a: Sign → verify round-trip succeeds", async () => {
  const secret = "test-secret-for-signing";
  const payload = JSON.stringify({ event: "scan.completed", files: 100 });
  const webhookId = "test-webhook-id";

  const headers = await signWebhookPayload(
    secret,
    payload,
    webhookId,
    "scan.completed",
  );

  // Verify signature
  const valid = await verifyWebhookSignature(
    secret,
    payload,
    headers["X-Drift-Signature"],
  );
  assert(valid, "Signature should verify with correct secret");
});

Deno.test("CT0-E-02b: Wrong secret → verification fails", async () => {
  const secret = "correct-secret";
  const payload = JSON.stringify({ event: "gate.failed" });

  const headers = await signWebhookPayload(
    secret,
    payload,
    "wh-id",
    "gate.failed",
  );

  const valid = await verifyWebhookSignature(
    "wrong-secret",
    payload,
    headers["X-Drift-Signature"],
  );
  assert(!valid, "Signature should NOT verify with wrong secret");
});

Deno.test("CT0-E-02c: Tampered payload → verification fails", async () => {
  const secret = "test-secret";
  const originalPayload = JSON.stringify({ event: "violation.new", line: 42 });
  const tamperedPayload = JSON.stringify({ event: "violation.new", line: 99 });

  const headers = await signWebhookPayload(
    secret,
    originalPayload,
    "wh-id",
    "violation.new",
  );

  const valid = await verifyWebhookSignature(
    secret,
    tamperedPayload,
    headers["X-Drift-Signature"],
  );
  assert(!valid, "Signature should NOT verify with tampered payload");
});

Deno.test("CT0-E-02d: Expired timestamp → verification fails", async () => {
  const secret = "test-secret";
  const payload = JSON.stringify({ event: "ping" });

  // Create a signature with a very old timestamp
  const oldTimestamp = Math.floor(Date.now() / 1000) - 600; // 10 min ago
  const signatureInput = `${oldTimestamp}.${payload}`;
  const hmac = await computeHmac(secret, signatureInput);
  const header = `t=${oldTimestamp},v1=${hmac}`;

  const valid = await verifyWebhookSignature(secret, payload, header, 300);
  assert(!valid, "Signature should NOT verify with expired timestamp (>5min)");
});

Deno.test("CT0-E-02e: Independently recomputed HMAC matches", async () => {
  const secret = "verify-independently";
  const payload = JSON.stringify({ event: "scan.completed", count: 5 });

  const headers = await signWebhookPayload(
    secret,
    payload,
    "wh-123",
    "scan.completed",
  );

  // Parse the signature header
  const parsed = parseSignatureHeader(headers["X-Drift-Signature"]);
  assert(parsed !== null, "Should parse signature header");

  // Independently recompute
  const expected = await computeHmac(
    secret,
    `${parsed!.timestamp}.${payload}`,
  );
  assertEquals(
    parsed!.signatures[0],
    expected,
    "Independently computed HMAC should match v1",
  );
});

Deno.test("CT0-E-02f: Rotation — both v1 and v2 present", async () => {
  const oldSecret = "old-secret";
  const newSecret = "new-secret";
  const payload = JSON.stringify({ event: "ping" });

  const headers = await signWebhookPayload(
    oldSecret,
    payload,
    "wh-rotate",
    "ping",
    newSecret,
  );

  const parsed = parseSignatureHeader(headers["X-Drift-Signature"]);
  assert(parsed !== null);
  assertEquals(parsed!.signatures.length, 2, "Should have both v1 and v2");

  // Old secret verifies via v1
  const validOld = await verifyWebhookSignature(
    oldSecret,
    payload,
    headers["X-Drift-Signature"],
  );
  assert(validOld, "Old secret should verify (v1)");

  // New secret verifies via v2
  const validNew = await verifyWebhookSignature(
    newSecret,
    payload,
    headers["X-Drift-Signature"],
  );
  assert(validNew, "New secret should verify (v2)");
});

Deno.test("CT0-E-02g: Headers include all required fields", async () => {
  const headers = await signWebhookPayload(
    "secret",
    "{}",
    "wh-id-123",
    "scan.completed",
  );

  assertEquals(headers["Content-Type"], "application/json");
  assert(headers["X-Drift-Signature"].startsWith("t="));
  assert(headers["X-Drift-Timestamp"].length > 0);
  assertEquals(headers["X-Drift-Webhook-Id"], "wh-id-123");
  assertEquals(headers["X-Drift-Event"], "scan.completed");
  assertEquals(headers["User-Agent"], "Drift-Webhooks/1.0");
});

// ── SHA-256 hash ──

Deno.test("sha256Hash produces consistent output", async () => {
  const hash1 = await sha256Hash("test-input");
  const hash2 = await sha256Hash("test-input");
  assertEquals(hash1, hash2, "Same input should produce same hash");
  assertEquals(hash1.length, 64, "SHA-256 hex should be 64 chars");
});

// ── Secret generation ──

Deno.test("generateWebhookSecret produces UUID-UUID format", () => {
  const secret = generateWebhookSecret();
  // UUID-UUID = 36 + 1 + 36 = 73 chars
  assert(secret.length === 73, `Expected 73 chars, got ${secret.length}`);
  assert(secret.includes("-"), "Should contain dashes");
});

// ── parseSignatureHeader ──

Deno.test("parseSignatureHeader handles valid input", () => {
  const parsed = parseSignatureHeader("t=1707660000,v1=abc123");
  assert(parsed !== null);
  assertEquals(parsed!.timestamp, 1707660000);
  assertEquals(parsed!.signatures, ["abc123"]);
});

Deno.test("parseSignatureHeader handles dual signatures", () => {
  const parsed = parseSignatureHeader("t=1707660000,v1=abc123,v2=def456");
  assert(parsed !== null);
  assertEquals(parsed!.signatures.length, 2);
  assertEquals(parsed!.signatures[0], "abc123");
  assertEquals(parsed!.signatures[1], "def456");
});

Deno.test("parseSignatureHeader rejects invalid input", () => {
  assertEquals(parseSignatureHeader(""), null);
  assertEquals(parseSignatureHeader("garbage"), null);
  assertEquals(parseSignatureHeader("t=notanumber,v1=abc"), null);
});

// ── URL validation (unit level) ──

Deno.test("URL validator: HTTPS valid URL → valid", () => {
  const result = validateWebhookUrl("https://example.com/webhook");
  assertEquals(result.valid, true);
});

Deno.test("URL validator: HTTP → invalid", () => {
  const result = validateWebhookUrl("http://example.com/webhook");
  assertEquals(result.valid, false);
  assert(result.error!.includes("HTTPS"));
});

Deno.test("URL validator: localhost → invalid", () => {
  assertEquals(validateWebhookUrl("https://localhost/hook").valid, false);
  assertEquals(validateWebhookUrl("https://127.0.0.1/hook").valid, false);
  assertEquals(validateWebhookUrl("https://0.0.0.0/hook").valid, false);
  assertEquals(validateWebhookUrl("https://[::1]/hook").valid, false);
});

Deno.test("URL validator: private IPs → invalid", () => {
  assertEquals(validateWebhookUrl("https://10.0.0.1/hook").valid, false);
  assertEquals(validateWebhookUrl("https://10.255.255.255/hook").valid, false);
  assertEquals(validateWebhookUrl("https://172.16.0.1/hook").valid, false);
  assertEquals(validateWebhookUrl("https://172.31.255.255/hook").valid, false);
  assertEquals(validateWebhookUrl("https://192.168.0.1/hook").valid, false);
  assertEquals(validateWebhookUrl("https://192.168.255.255/hook").valid, false);
  assertEquals(validateWebhookUrl("https://169.254.1.1/hook").valid, false);
});

Deno.test("URL validator: public IPs → valid", () => {
  assertEquals(validateWebhookUrl("https://8.8.8.8/hook").valid, true);
  assertEquals(validateWebhookUrl("https://1.1.1.1/hook").valid, true);
  assertEquals(validateWebhookUrl("https://203.0.113.1/hook").valid, true);
});

Deno.test("URL validator: invalid URL → invalid", () => {
  assertEquals(validateWebhookUrl("not a url").valid, false);
  assertEquals(validateWebhookUrl("").valid, false);
});

// 172.15.x is NOT private (only 172.16-31)
Deno.test("URL validator: 172.15.x → valid (not in private range)", () => {
  assertEquals(validateWebhookUrl("https://172.15.0.1/hook").valid, true);
});

// 172.32.x is NOT private
Deno.test("URL validator: 172.32.x → valid (not in private range)", () => {
  assertEquals(validateWebhookUrl("https://172.32.0.1/hook").valid, true);
});
