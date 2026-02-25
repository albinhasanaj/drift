// Phase E: Webhook URL Validator (CP0-E-02)
// HTTPS-only, block localhost and private IP ranges (SSRF prevention)

/** Result of URL validation */
export interface UrlValidationResult {
  valid: boolean;
  error?: string;
}

// Private/reserved IPv4 CIDR ranges
const PRIVATE_RANGES = [
  { prefix: "10.", mask: 8 },       // 10.0.0.0/8
  { prefix: "172.", start: 16, end: 31 }, // 172.16.0.0/12
  { prefix: "192.168.", mask: 16 },  // 192.168.0.0/16
  { prefix: "169.254.", mask: 16 },  // 169.254.0.0/16 (link-local)
  { prefix: "127.", mask: 8 },       // 127.0.0.0/8 (loopback)
];

const BLOCKED_HOSTNAMES = [
  "localhost",
  "0.0.0.0",
  "::1",
  "[::1]",
  "[::]",
];

/**
 * Validate a webhook URL.
 * Rules:
 * - Must be valid URL
 * - Must use HTTPS (not HTTP)
 * - Must not target localhost or loopback addresses
 * - Must not target private IP ranges (SSRF prevention)
 */
export function validateWebhookUrl(urlString: string): UrlValidationResult {
  // Parse URL
  let url: URL;
  try {
    url = new URL(urlString);
  } catch {
    return { valid: false, error: "Invalid URL format" };
  }

  // HTTPS only
  if (url.protocol !== "https:") {
    return {
      valid: false,
      error: "Webhook URLs must use HTTPS. HTTP is not allowed.",
    };
  }

  // Block known dangerous hostnames
  const hostname = url.hostname.toLowerCase();
  if (BLOCKED_HOSTNAMES.includes(hostname)) {
    return {
      valid: false,
      error: `Webhook URLs cannot target ${hostname}`,
    };
  }

  // Check if hostname is an IP address
  if (isIPv4(hostname)) {
    if (isPrivateIPv4(hostname)) {
      return {
        valid: false,
        error: "Webhook URLs cannot target private IP addresses",
      };
    }
  }

  // Check for IPv6 loopback in brackets
  if (hostname.startsWith("[") && hostname.endsWith("]")) {
    const ipv6 = hostname.slice(1, -1);
    if (ipv6 === "::1" || ipv6 === "::") {
      return {
        valid: false,
        error: "Webhook URLs cannot target loopback addresses",
      };
    }
  }

  return { valid: true };
}

function isIPv4(hostname: string): boolean {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    return false;
  }

  // 127.0.0.0/8
  if (parts[0] === 127) return true;

  // 10.0.0.0/8
  if (parts[0] === 10) return true;

  // 172.16.0.0/12
  if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;

  // 192.168.0.0/16
  if (parts[0] === 192 && parts[1] === 168) return true;

  // 169.254.0.0/16 (link-local)
  if (parts[0] === 169 && parts[1] === 254) return true;

  // 0.0.0.0
  if (parts.every((p) => p === 0)) return true;

  return false;
}
