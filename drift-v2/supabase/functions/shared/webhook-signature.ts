// Phase E: Webhook HMAC-SHA256 Signature (CP0-E-03)
// Stripe-pattern: X-Drift-Signature: t=epoch,v1=hmac[,v2=hmac_new]
// Constant-time comparison via timingSafeEqual()

import { SIGNATURE_TOLERANCE_SECONDS } from "./webhook-types.ts";

/** Headers attached to every webhook delivery */
export type WebhookDeliveryHeaders = Record<string, string>;

/**
 * Sign a webhook payload with HMAC-SHA256.
 * Returns all headers for the delivery.
 *
 * During rotation (when both old and new secrets exist):
 *   X-Drift-Signature: t=epoch,v1=hmac_old,v2=hmac_new
 */
export async function signWebhookPayload(
  secret: string,
  payload: string,
  webhookId: string,
  eventType: string,
  secretNew?: string,
): Promise<WebhookDeliveryHeaders> {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signatureInput = `${timestamp}.${payload}`;

  const v1 = await computeHmac(secret, signatureInput);

  let signatureValue = `t=${timestamp},v1=${v1}`;
  if (secretNew) {
    const v2 = await computeHmac(secretNew, signatureInput);
    signatureValue += `,v2=${v2}`;
  }

  return {
    "Content-Type": "application/json",
    "X-Drift-Signature": signatureValue,
    "X-Drift-Timestamp": timestamp,
    "X-Drift-Webhook-Id": webhookId,
    "X-Drift-Event": eventType,
    "User-Agent": "Drift-Webhooks/1.0",
  };
}

/**
 * Verify a webhook signature.
 * Checks both v1 and v2 (if present) against the provided secret.
 * Uses constant-time comparison.
 */
export async function verifyWebhookSignature(
  secret: string,
  payload: string,
  signatureHeader: string,
  toleranceSeconds: number = SIGNATURE_TOLERANCE_SECONDS,
): Promise<boolean> {
  const parsed = parseSignatureHeader(signatureHeader);
  if (!parsed) return false;

  // Check timestamp tolerance
  const now = Math.floor(Date.now() / 1000);
  const diff = Math.abs(now - parsed.timestamp);
  if (diff > toleranceSeconds) return false;

  // Recompute expected HMAC
  const signatureInput = `${parsed.timestamp}.${payload}`;
  const expected = await computeHmac(secret, signatureInput);

  // Check v1 first, then v2
  for (const sig of parsed.signatures) {
    if (await timingSafeCompare(sig, expected)) {
      return true;
    }
  }

  return false;
}

/**
 * Parse signature header: t=epoch,v1=hex[,v2=hex]
 */
export function parseSignatureHeader(
  header: string,
): { timestamp: number; signatures: string[] } | null {
  const parts = header.split(",");
  let timestamp = 0;
  const signatures: string[] = [];

  for (const part of parts) {
    const [key, value] = part.split("=", 2);
    if (!key || !value) return null;

    if (key === "t") {
      timestamp = parseInt(value, 10);
      if (isNaN(timestamp)) return null;
    } else if (key.startsWith("v")) {
      signatures.push(value);
    }
  }

  if (timestamp === 0 || signatures.length === 0) return null;
  return { timestamp, signatures };
}

/**
 * Compute HMAC-SHA256 and return hex string.
 */
export async function computeHmac(
  secret: string,
  message: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(message),
  );
  return arrayBufferToHex(signature);
}

/**
 * Compute SHA-256 hash and return hex string.
 */
export async function sha256Hash(input: string): Promise<string> {
  const encoder = new TextEncoder();
  const hash = await crypto.subtle.digest("SHA-256", encoder.encode(input));
  return arrayBufferToHex(hash);
}

/**
 * Generate a crypto-random webhook secret.
 * Format: UUID-UUID (64 hex chars with dashes)
 */
export function generateWebhookSecret(): string {
  return `${crypto.randomUUID()}-${crypto.randomUUID()}`;
}

/**
 * Constant-time string comparison to prevent timing attacks.
 */
async function timingSafeCompare(a: string, b: string): Promise<boolean> {
  const encoder = new TextEncoder();
  const aBuf = encoder.encode(a);
  const bBuf = encoder.encode(b);

  if (aBuf.length !== bBuf.length) return false;

  // Use subtle crypto for constant-time comparison
  const key = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(32),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const sigA = await crypto.subtle.sign("HMAC", key, aBuf);
  const sigB = await crypto.subtle.sign("HMAC", key, bBuf);

  const viewA = new Uint8Array(sigA);
  const viewB = new Uint8Array(sigB);

  let result = 0;
  for (let i = 0; i < viewA.length; i++) {
    result |= viewA[i] ^ viewB[i];
  }
  return result === 0;
}

function arrayBufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
