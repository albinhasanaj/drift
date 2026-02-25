/**
 * Shared project root resolution — single source of truth for all entry points.
 *
 * Precedence (highest to lowest):
 *   1. Explicit path (--project-root, --path flag)
 *   2. DRIFT_PROJECT_ROOT environment variable
 *   3. Upward directory search for .drift/ (like git finds .git/)
 *   4. process.cwd() fallback
 *
 * This replaces fragile argv-sniffing patterns that broke when CLI arg values
 * (e.g. 'json', 'bridge') collided with directory names in the repo.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Resolve the project root directory.
 *
 * @param explicit - An explicitly provided path (from --project-root or --path flag).
 *                   If provided, this always wins — no heuristics applied.
 * @returns Absolute path to the project root.
 */
export function resolveProjectRoot(explicit?: string): string {
  // 1. Explicit flag — highest priority, no guessing
  if (explicit) {
    return path.resolve(explicit);
  }

  // 2. Environment variable — useful for CI/containers
  const envRoot = process.env['DRIFT_PROJECT_ROOT'];
  if (envRoot) {
    return path.resolve(envRoot);
  }

  // 3. Walk upward from cwd looking for .drift/ directory
  //    Same pattern as git (.git/), cargo (Cargo.toml), npm (package.json)
  const found = findUpward('.drift');
  if (found) {
    return found;
  }

  // 4. Fallback to cwd
  return process.cwd();
}

/**
 * Walk upward from cwd looking for a directory with the given name.
 * Returns the parent directory containing it, or undefined if not found.
 */
function findUpward(targetDir: string): string | undefined {
  let dir = process.cwd();
  const root = path.parse(dir).root;

  while (true) {
    try {
      const candidate = path.join(dir, targetDir);
      if (fs.statSync(candidate).isDirectory()) {
        return dir;
      }
    } catch {
      // Not found at this level — keep climbing
    }

    if (dir === root) break;
    const parent = path.dirname(dir);
    if (parent === dir) break; // safety: shouldn't happen but prevents infinite loop
    dir = parent;
  }

  return undefined;
}
