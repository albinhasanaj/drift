/**
 * Cloud authentication — JWT credential management for Supabase.
 *
 * Stores credentials in ~/.drift/cloud-credentials.json.
 * Uses Supabase Auth REST API for token refresh.
 */

import { readFile, writeFile, mkdir, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { CloudCredentials } from './config.js';
import { CREDENTIALS_PATH } from './config.js';

function credentialsFilePath(): string {
  return join(homedir(), CREDENTIALS_PATH);
}

/**
 * Store credentials to disk.
 */
export async function saveCredentials(creds: CloudCredentials): Promise<void> {
  const filePath = credentialsFilePath();
  const dir = filePath.substring(0, filePath.lastIndexOf('/'));
  await mkdir(dir, { recursive: true });
  await writeFile(filePath, JSON.stringify(creds, null, 2), { mode: 0o600 });
}

/**
 * Load credentials from disk. Returns null if not found.
 */
export async function loadCredentials(): Promise<CloudCredentials | null> {
  try {
    const raw = await readFile(credentialsFilePath(), 'utf-8');
    return JSON.parse(raw) as CloudCredentials;
  } catch {
    return null;
  }
}

/**
 * Get a valid access token — refreshes if expired.
 * Returns null if no credentials exist.
 */
export async function getToken(supabaseUrl: string, supabaseAnonKey: string): Promise<string | null> {
  const creds = await loadCredentials();
  if (!creds) return null;

  // Check if token is expired (with 60s buffer)
  const expiresAt = new Date(creds.expiresAt).getTime();
  const now = Date.now();
  if (now < expiresAt - 60_000) {
    return creds.accessToken;
  }

  // Token expired — refresh
  const refreshed = await refreshToken(supabaseUrl, supabaseAnonKey, creds.refreshToken);
  if (!refreshed) return null;

  await saveCredentials(refreshed);
  return refreshed.accessToken;
}

/**
 * Refresh an access token using the refresh token.
 * Returns new credentials or null on failure.
 */
export async function refreshToken(
  supabaseUrl: string,
  supabaseAnonKey: string,
  refreshTokenValue: string,
): Promise<CloudCredentials | null> {
  try {
    const response = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=refresh_token`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'apikey': supabaseAnonKey,
      },
      body: JSON.stringify({ refresh_token: refreshTokenValue }),
    });

    if (!response.ok) return null;

    const data = await response.json() as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token,
      expiresAt: new Date(Date.now() + data.expires_in * 1000).toISOString(),
    };
  } catch {
    return null;
  }
}

/**
 * Clear stored credentials (logout).
 */
export async function logout(): Promise<void> {
  try {
    await unlink(credentialsFilePath());
  } catch {
    // File doesn't exist — that's fine
  }
}

/**
 * Check if the user is logged in (has credentials on disk).
 */
export async function isLoggedIn(): Promise<boolean> {
  const creds = await loadCredentials();
  return creds !== null;
}
