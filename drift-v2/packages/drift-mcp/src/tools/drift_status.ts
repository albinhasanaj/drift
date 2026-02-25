/**
 * drift_status — project overview composed from NAPI contract methods.
 *
 * Performance target: <1ms (reads pre-computed data).
 * Returns: version, file count, pattern count, violation count, health score, gate status.
 */

import { loadNapi } from '../napi.js';
import type { StatusOverview } from '../types.js';

/** JSON Schema for drift_status parameters. */
export const DRIFT_STATUS_SCHEMA = {
  type: 'object' as const,
  properties: {},
  additionalProperties: false,
};

/**
 * Execute drift_status — composes overview from NAPI contract methods.
 * Queries real data from DB for file count, pattern count, violations, health.
 */
export async function handleDriftStatus(): Promise<StatusOverview> {
  const napi = loadNapi();
  const isInit = napi.driftIsInitialized();

  if (!isInit) {
    return {
      version: '2.0.0',
      projectRoot: '.',
      fileCount: 0,
      patternCount: 0,
      violationCount: 0,
      healthScore: 100,
      lastScanTime: null,
      gateStatus: 'unknown',
    };
  }

  const violations = napi.driftViolations('.');
  const checkResult = napi.driftCheck('.');
  const audit = napi.driftAudit('.');
  const patterns = napi.driftPatterns();

  // Call graph gives us real file/function counts from DB
  let fileCount = 0;
  try {
    const cg = await napi.driftCallGraph();
    // total_functions is a proxy for tracked file count when no direct query exists
    fileCount = cg.totalFunctions;
  } catch {
    // Non-fatal — call graph may not be populated yet
  }

  return {
    version: '2.0.0',
    projectRoot: '.',
    fileCount,
    patternCount: patterns.patterns.length,
    violationCount: violations.length,
    healthScore: audit.healthScore,
    lastScanTime: null,
    gateStatus: checkResult.overallPassed ? 'passed' : 'failed',
  };
}
