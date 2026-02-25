/**
 * Cortex initialization helper for the drift MCP server.
 *
 * Provides lazy singleton CortexClient init/shutdown, used by cortex tool handlers.
 */

import { CortexClient } from '@drift/cortex';

let cortexClient: CortexClient | null = null;
let cortexInitPromise: Promise<CortexClient> | null = null;

/**
 * Initialize the Cortex runtime with a lazy singleton.
 * Safe to call multiple times — returns the existing client if already initialized.
 *
 * @param dbPath - Path to SQLite database. Null for in-memory.
 */
export async function initCortex(dbPath?: string): Promise<CortexClient> {
  if (cortexClient) return cortexClient;

  // Prevent double-init race
  if (cortexInitPromise) return cortexInitPromise;

  cortexInitPromise = CortexClient.initialize({
    dbPath: dbPath ?? null,
  }).then((client: CortexClient) => {
    cortexClient = client;
    cortexInitPromise = null;
    return client;
  }).catch((err: unknown) => {
    cortexInitPromise = null;
    throw err;
  });

  return cortexInitPromise;
}

/**
 * Get the initialized CortexClient, or throw if not yet initialized.
 */
export function getCortex(): CortexClient {
  if (!cortexClient) {
    throw new Error(
      'Cortex not initialized. Call initCortex() first, or ensure cortexEnabled is true in MCP config.',
    );
  }
  return cortexClient;
}

/**
 * Check if Cortex is initialized.
 */
export function isCortexInitialized(): boolean {
  return cortexClient !== null;
}

/**
 * Graceful Cortex shutdown. Idempotent — safe to call multiple times.
 */
export async function shutdownCortex(): Promise<void> {
  if (!cortexClient) return;
  try {
    await cortexClient.shutdown();
  } catch {
    // Non-fatal — best-effort shutdown
  } finally {
    cortexClient = null;
    cortexInitPromise = null;
  }
}
