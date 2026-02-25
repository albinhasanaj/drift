/**
 * drift_scan — trigger analysis on the project.
 *
 * Calls NAPI driftScan() to run the full analysis pipeline.
 * Supports incremental mode for faster re-scans.
 */

import { loadNapi } from '../napi.js';
import type { DriftScanParams, ScanResult } from '../types.js';

/** JSON Schema for drift_scan parameters. */
export const DRIFT_SCAN_SCHEMA = {
  type: 'object' as const,
  properties: {
    path: {
      type: 'string',
      description: 'Path to scan (defaults to project root)',
    },
    incremental: {
      type: 'boolean',
      description: 'Only scan changed files since last scan',
      default: false,
    },
  },
  additionalProperties: false,
};

/**
 * Execute drift_scan — triggers scan + analysis pipeline.
 *
 * 1. Runs driftScan() to persist file metadata
 * 2. Runs drift_analyze() to populate detections, patterns, call graph, boundaries
 * 3. Returns real pattern/violation counts from analysis results
 */
export async function handleDriftScan(
  params: DriftScanParams,
): Promise<ScanResult> {
  const napi = loadNapi();
  const scanPath = params.path ?? process.cwd();
  const options = params.incremental ? { forceFull: false } : undefined;

  // Step 1: Scan files
  const summary = await napi.driftScan(scanPath, options);

  // Step 2: Run full analysis pipeline (populates DB with detections, patterns, etc.)
  const analysisResults = await napi.driftAnalyze();
  const totalPatterns = analysisResults.reduce(
    (sum, r) => sum + r.matches.length,
    0,
  );

  // Step 2b: Bridge grounding — validate bridge memories against drift.db evidence
  try {
    napi.driftBridgeGroundAfterAnalyze();
  } catch {
    // Non-fatal: grounding failure doesn't affect scan results
  }

  // Step 3: Query violations from DB (populated by analysis)
  const violations = napi.driftViolations('.');

  return {
    filesScanned: summary.filesTotal,
    patternsDetected: totalPatterns,
    violationsFound: violations.length,
    durationMs: summary.durationMs,
  };
}
