/**
 * SARIF Upload — uploads SARIF to GitHub Code Scanning API.
 *
 * Uses the GitHub REST API to upload SARIF analysis results.
 * Handles authentication, compression, and error handling.
 */

import * as fs from 'node:fs';
import * as zlib from 'node:zlib';

/** SARIF upload configuration. */
export interface SarifUploadConfig {
  /** GitHub API token. */
  token: string;
  /** Repository owner. */
  owner: string;
  /** Repository name. */
  repo: string;
  /** Git commit SHA. */
  commitSha: string;
  /** Git ref (e.g., refs/heads/main). */
  ref: string;
  /** Path to SARIF file. */
  sarifPath: string;
  /** GitHub API base URL (for GHES). */
  apiUrl?: string;
}

/** SARIF upload result. */
export interface SarifUploadResult {
  success: boolean;
  id?: string;
  url?: string;
  error?: string;
}

/**
 * Upload SARIF file to GitHub Code Scanning.
 */
export async function uploadSarif(
  config: SarifUploadConfig,
): Promise<SarifUploadResult> {
  const apiUrl = config.apiUrl ?? 'https://api.github.com';

  try {
    // Read and compress SARIF
    const sarifContent = fs.readFileSync(config.sarifPath, 'utf-8');
    const compressed = zlib.gzipSync(Buffer.from(sarifContent, 'utf-8'));
    const base64Sarif = compressed.toString('base64');

    // Upload via GitHub API
    const url = `${apiUrl}/repos/${config.owner}/${config.repo}/code-scanning/sarifs`;

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${config.token}`,
        Accept: 'application/vnd.github+json',
        'Content-Type': 'application/json',
        'X-GitHub-Api-Version': '2022-11-28',
      },
      body: JSON.stringify({
        commit_sha: config.commitSha,
        ref: config.ref,
        sarif: base64Sarif,
        tool_name: 'drift',
      }),
    });

    if (response.ok || response.status === 202) {
      const data = (await response.json()) as { id?: string; url?: string };
      return {
        success: true,
        id: data.id,
        url: data.url,
      };
    }

    const errorText = await response.text();
    return {
      success: false,
      error: `GitHub API returned ${response.status}: ${errorText}`,
    };
  } catch (err) {
    return {
      success: false,
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Write SARIF content to a file for later upload.
 */
export function writeSarifFile(
  violations: unknown[],
  outputPath: string,
): void {
  const sarif = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'drift',
            version: '2.0.0',
            informationUri: 'https://github.com/drift-lang/drift',
          },
        },
        results: violations.map((v: unknown) => {
          const violation = v as Record<string, unknown>;
          return {
            ruleId: violation.rule_id ?? violation.ruleId ?? 'unknown',
            level: mapSeverity(violation.severity as string),
            message: { text: (violation.message as string) ?? 'Violation detected' },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: {
                    uri: violation.file ?? 'unknown',
                    uriBaseId: '%SRCROOT%',
                  },
                  region: {
                    startLine: Math.max((violation.line as number) ?? 1, 1),
                  },
                },
              },
            ],
          };
        }),
      },
    ],
  };

  fs.writeFileSync(outputPath, JSON.stringify(sarif, null, 2), 'utf-8');
}

/**
 * Write SARIF file using the native driftReport() engine.
 * Produces richer output than manual conversion (includes taxonomies, CWE data, etc.)
 */
export function writeSarifFromNapi(outputPath: string): void {
  const { loadNapi } = require('./napi.js') as { loadNapi: () => { driftReport: (format: string) => string } };
  const napi = loadNapi();
  const sarif = napi.driftReport('sarif');
  fs.writeFileSync(outputPath, sarif, 'utf-8');
}

function mapSeverity(severity?: string): string {
  switch (severity?.toLowerCase()) {
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    default:
      return 'note';
  }
}
