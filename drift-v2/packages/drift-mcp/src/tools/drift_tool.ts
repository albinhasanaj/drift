/**
 * drift_tool — dynamic dispatch for ~105 internal tools (30 drift + 12 bridge + 63 cortex).
 *
 * Progressive disclosure: AI agent sees 3-4 tools initially, discovers
 * more via drift_tool. This reduces token overhead ~81% compared to
 * registering all tools individually.
 *
 * The AI agent calls drift_tool with a tool name and parameters,
 * and this handler routes to the correct NAPI function.
 */

import { loadNapi } from '../napi.js';
import type { DriftToolParams, InternalTool } from '../types.js';
import type { InfrastructureLayer } from '../infrastructure/index.js';
import { ErrorHandler } from '../infrastructure/error_handler.js';
import { ResponseCache } from '../infrastructure/cache.js';
import { registerCortexTools, CORTEX_CACHEABLE_TOOLS, CORTEX_MUTATION_TOOLS } from './cortex_tools.js';

/** Tools that mutate state — cache is invalidated after these run. */
const MUTATION_TOOLS = new Set([
  'drift_scan_progress', 'drift_cancel_scan', 'drift_analyze',
  'drift_dismiss', 'drift_fix', 'drift_suppress', 'drift_gc',
  'drift_approve_pattern',
  // Bridge mutation tools
  'drift_bridge_ground', 'drift_bridge_ground_all', 'drift_bridge_learn',
]);

/** Tools whose results are safe to cache (read-only queries). */
const CACHEABLE_TOOLS = new Set([
  'drift_status', 'drift_capabilities', 'drift_patterns_list',
  'drift_security_summary', 'drift_trends', 'drift_coupling',
  'drift_test_topology', 'drift_error_handling', 'drift_quality_gate',
  'drift_constants', 'drift_constraints', 'drift_audit', 'drift_owasp',
  'drift_crypto', 'drift_decomposition', 'drift_contracts',
  'drift_outliers', 'drift_conventions', 'drift_dna_profile', 'drift_pattern_status',
  'drift_wrappers', 'drift_callers', 'drift_impact_analysis',
  // Bridge cacheable tools
  'drift_bridge_status', 'drift_bridge_health', 'drift_bridge_events',
  'drift_bridge_grounding_history', 'drift_bridge_memories',
]);

/** JSON Schema for drift_tool parameters. */
export const DRIFT_TOOL_SCHEMA = {
  type: 'object' as const,
  properties: {
    tool: {
      type: 'string',
      description: 'Internal tool name (use drift_status to discover available tools)',
    },
    params: {
      type: 'object',
      description: 'Tool-specific parameters',
      additionalProperties: true,
    },
  },
  required: ['tool'],
  additionalProperties: false,
};

/** Build the internal tool catalog with NAPI-backed handlers. */
export function buildToolCatalog(): Map<string, InternalTool> {
  const catalog = new Map<string, InternalTool>();

  // Discovery tools
  register(catalog, {
    name: 'drift_status',
    description: 'Health snapshot (patterns, violations, storage)',
    category: 'discovery',
    estimatedTokens: '~200',
    handler: async () => {
      const napi = loadNapi();
      return {
        version: '2.0.0',
        initialized: napi.driftIsInitialized(),
        violations: napi.driftViolations('.').length,
        healthScore: napi.driftAudit('.').healthScore,
        gateStatus: napi.driftCheck('.').overallPassed ? 'passed' : 'failed',
      };
    },
  });
  register(catalog, {
    name: 'drift_capabilities',
    description: 'Full tool listing with descriptions',
    category: 'discovery',
    estimatedTokens: '~500',
    handler: async () => listCapabilities(catalog),
  });

  // Surgical tools
  register(catalog, {
    name: 'drift_callers',
    description: 'Who calls this function',
    category: 'surgical',
    estimatedTokens: '~200-500',
    handler: async () => loadNapi().driftCallGraph(),
  });
  register(catalog, {
    name: 'drift_reachability',
    description: 'Data flow reachability from a function',
    category: 'surgical',
    estimatedTokens: '~1000-3000',
    handler: async (p) => loadNapi().driftReachability(p.functionKey as string, (p.direction as string) ?? 'forward'),
  });
  register(catalog, {
    name: 'drift_prevalidate',
    description: 'Quick pre-write validation',
    category: 'surgical',
    estimatedTokens: '~300-800',
    handler: async (p) => loadNapi().driftCheck(p.path as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_similar',
    description: 'Find similar code patterns',
    category: 'surgical',
    estimatedTokens: '~500-1500',
    handler: async (p) => loadNapi().driftPatterns(p.category as string | undefined, p.afterId as string | undefined, p.limit as number | undefined),
  });

  // Exploration tools
  register(catalog, {
    name: 'drift_patterns_list',
    description: 'List patterns with filters + pagination',
    category: 'exploration',
    estimatedTokens: '~500-1500',
    handler: async (p) => loadNapi().driftPatterns(p.category as string | undefined, p.afterId as string | undefined, p.limit as number | undefined),
  });
  register(catalog, {
    name: 'drift_security_summary',
    description: 'Security posture overview',
    category: 'exploration',
    estimatedTokens: '~800-2000',
    handler: async (p) => loadNapi().driftOwaspAnalysis(p.path as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_trends',
    description: 'Pattern trends over time',
    category: 'exploration',
    estimatedTokens: '~500-1500',
    handler: async (p) => loadNapi().driftAudit(p.root as string ?? '.'),
  });

  // Detail tools
  register(catalog, {
    name: 'drift_impact_analysis',
    description: 'Change blast radius analysis',
    category: 'detail',
    estimatedTokens: '~1000-3000',
    handler: async (p) => loadNapi().driftImpactAnalysis(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_taint',
    description: 'Taint flow analysis (source → sink)',
    category: 'detail',
    estimatedTokens: '~1000-3000',
    handler: async (p) => loadNapi().driftTaintAnalysis(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_dna_profile',
    description: 'Styling DNA profile for a module',
    category: 'detail',
    estimatedTokens: '~800-2000',
    handler: async (p) => loadNapi().driftDnaAnalysis(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_wrappers',
    description: 'Framework wrapper detection',
    category: 'detail',
    estimatedTokens: '~500-1500',
    handler: async (p) => loadNapi().driftWrapperDetection(p.root as string ?? '.'),
  });

  // Analysis tools
  register(catalog, {
    name: 'drift_coupling',
    description: 'Module coupling analysis (Martin metrics)',
    category: 'analysis',
    estimatedTokens: '~1000-2500',
    handler: async (p) => loadNapi().driftCouplingAnalysis(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_test_topology',
    description: 'Test coverage and quality analysis',
    category: 'analysis',
    estimatedTokens: '~1000-2500',
    handler: async (p) => loadNapi().driftTestTopology(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_error_handling',
    description: 'Error handling gap analysis',
    category: 'analysis',
    estimatedTokens: '~800-2000',
    handler: async (p) => loadNapi().driftErrorHandling(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_quality_gate',
    description: 'Quality gate checks',
    category: 'analysis',
    estimatedTokens: '~1500-4000',
    handler: async (p) => loadNapi().driftGates(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_constants',
    description: 'Constants and secrets analysis',
    category: 'analysis',
    estimatedTokens: '~800-2000',
    handler: async (p) => loadNapi().driftConstantsAnalysis(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_constraints',
    description: 'Constraint verification',
    category: 'analysis',
    estimatedTokens: '~800-2000',
    handler: async (p) => loadNapi().driftConstraintVerification(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_audit',
    description: 'Full pattern audit with health scoring',
    category: 'analysis',
    estimatedTokens: '~1000-3000',
    handler: async (p) => loadNapi().driftAudit(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_decisions',
    description: 'Decision mining from git history',
    category: 'analysis',
    estimatedTokens: '~800-2000',
    handler: async (p) => loadNapi().driftDecisions(p.repoPath as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_simulate',
    description: 'Speculative execution / Monte Carlo simulation',
    category: 'analysis',
    estimatedTokens: '~2000-5000',
    handler: async (p) => loadNapi().driftSimulate(
      p.category as string ?? 'refactor',
      p.description as string ?? '',
      p.contextJson as string ?? '{}',
    ),
  });

  // Generation tools
  register(catalog, {
    name: 'drift_explain',
    description: 'Comprehensive code explanation',
    category: 'generation',
    estimatedTokens: '~2000-5000',
    handler: async (p) => loadNapi().driftContext(p.query as string ?? '', 'deep', '{}'),
  });
  register(catalog, {
    name: 'drift_validate_change',
    description: 'Validate code against patterns',
    category: 'generation',
    estimatedTokens: '~1000-3000',
    handler: async (p) => loadNapi().driftCheck(p.root as string ?? '.'),
  });
  register(catalog, {
    name: 'drift_suggest_changes',
    description: 'Suggest pattern-aligned changes',
    category: 'generation',
    estimatedTokens: '~1000-3000',
    handler: async (p) => loadNapi().driftViolations(p.root as string ?? '.'),
  });

  // Setup tools
  register(catalog, {
    name: 'drift_generate_spec',
    description: 'Generate specification for a module',
    category: 'generation',
    estimatedTokens: '~1000-3000',
    handler: async (p) => loadNapi().driftGenerateSpec(p.moduleJson as string ?? '{}', p.migrationPathJson as string | undefined),
  });

  // --- C3: Missing tools with Rust NAPI backing ---

  // PH-TOOL-14: drift_outliers
  register(catalog, {
    name: 'drift_outliers',
    description: 'Detect statistical outliers using auto-selected method (Z-Score/Grubbs/ESD). Supports pagination.',
    category: 'exploration',
    estimatedTokens: '~400',
    handler: async (p) => loadNapi().driftOutliers(p.patternId as string | undefined, p.afterId as number | undefined, p.limit as number | undefined),
  });

  // PH-TOOL-15: drift_conventions
  register(catalog, {
    name: 'drift_conventions',
    description: 'Discover learned coding conventions with Bayesian confidence scores.',
    category: 'exploration',
    estimatedTokens: '~500',
    handler: async (p) => loadNapi().driftConventions(p.category as string | undefined, p.afterId as number | undefined, p.limit as number | undefined),
  });

  // PH-TOOL-16: drift_owasp
  register(catalog, {
    name: 'drift_owasp',
    description: 'OWASP Top 10 analysis with CWE mapping and compliance scoring.',
    category: 'analysis',
    estimatedTokens: '~600',
    handler: async (p) => loadNapi().driftOwaspAnalysis(p.root as string ?? '.'),
  });

  // PH-TOOL-17: drift_crypto
  register(catalog, {
    name: 'drift_crypto',
    description: 'Cryptographic failure detection mapped to CWE-310/327/328.',
    category: 'analysis',
    estimatedTokens: '~400',
    handler: async (p) => loadNapi().driftCryptoAnalysis(p.root as string ?? '.'),
  });

  // PH-TOOL-18: drift_decomposition
  register(catalog, {
    name: 'drift_decomposition',
    description: 'Module decomposition with cohesion/coupling metrics and boundary suggestions.',
    category: 'analysis',
    estimatedTokens: '~800',
    handler: async (p) => loadNapi().driftDecomposition(p.root as string ?? '.'),
  });

  // PH-TOOL-19: drift_contracts
  register(catalog, {
    name: 'drift_contracts',
    description: 'API contract detection across 7 paradigms. Finds frontend↔backend mismatches.',
    category: 'exploration',
    estimatedTokens: '~600',
    handler: async (p) => loadNapi().driftContractTracking(p.root as string ?? '.'),
  });

  // PH-TOOL-20: drift_dismiss
  register(catalog, {
    name: 'drift_dismiss',
    description: 'Dismiss violation with reason. Adjusts Bayesian confidence.',
    category: 'feedback',
    estimatedTokens: '~50',
    handler: async (p) => loadNapi().driftDismissViolation({ violationId: p.violationId as string, action: 'dismiss', reason: p.reason as string }),
  });

  // PH-TOOL-21: drift_fix
  register(catalog, {
    name: 'drift_fix',
    description: 'Mark violation fixed. Positive Bayesian signal.',
    category: 'feedback',
    estimatedTokens: '~50',
    handler: async (p) => loadNapi().driftFixViolation(p.violationId as string),
  });

  // PH-TOOL-22: drift_suppress
  register(catalog, {
    name: 'drift_suppress',
    description: 'Suppress violation for N days. Auto-unsuppresses.',
    category: 'feedback',
    estimatedTokens: '~50',
    handler: async (p) => loadNapi().driftSuppressViolation(p.violationId as string, p.reason as string ?? 'suppressed'),
  });

  // PH-TOOL-28: drift_approve_pattern — approve or ignore a pattern
  register(catalog, {
    name: 'drift_approve_pattern',
    description: 'Approve or ignore a pattern. Sets lifecycle status (approved/ignored/discovered). User approval overrides auto-approval.',
    category: 'feedback',
    estimatedTokens: '~100',
    handler: async (p) => loadNapi().driftApprovePattern(
      p.patternId as string,
      (p.status as string) ?? 'approved',
      (p.reason as string | undefined) ?? null,
    ),
  });

  // PH-TOOL-29: drift_pattern_status — query pattern lifecycle statuses
  register(catalog, {
    name: 'drift_pattern_status',
    description: 'Query pattern lifecycle statuses. Shows discovered/approved/ignored patterns with counts. Filter by status.',
    category: 'exploration',
    estimatedTokens: '~300-800',
    handler: async (p) => loadNapi().driftPatternStatus((p.status as string | undefined) ?? null),
  });

  // PH-TOOL-23: drift_scan_progress
  register(catalog, {
    name: 'drift_scan_progress',
    description: 'Scan with real-time progress reporting.',
    category: 'operational',
    estimatedTokens: '~100',
    handler: async (p) => loadNapi().driftScanWithProgress(
      p.path as string ?? '.',
      p.options as Record<string, unknown> | undefined,
      (update) => {
        // PH6-04: Log scan progress so MCP transport can relay as notifications
        console.log(JSON.stringify({ type: 'scan_progress', ...update }));
      },
    ),
  });

  // PH-TOOL-24: drift_cancel_scan
  register(catalog, {
    name: 'drift_cancel_scan',
    description: 'Cancel a running scan.',
    category: 'operational',
    estimatedTokens: '~30',
    handler: async () => loadNapi().driftCancelScan(),
  });

  // PH-TOOL-25: drift_analyze — run full analysis pipeline (separate from scan)
  register(catalog, {
    name: 'drift_analyze',
    description: 'Run full analysis pipeline on already-scanned files. Populates detections, patterns, call graph, boundaries, conventions. Requires prior scan.',
    category: 'operational',
    estimatedTokens: '~500-2000',
    handler: async () => {
      const results = await loadNapi().driftAnalyze();
      const totalMatches = results.reduce((sum, r) => sum + r.matches.length, 0);
      return {
        filesAnalyzed: results.length,
        patternsDetected: totalMatches,
        languages: [...new Set(results.map((r) => r.language))],
      };
    },
  });

  // PH-TOOL-26: drift_report — generate reports in 8 formats
  register(catalog, {
    name: 'drift_report',
    description: 'Generate report from stored violations. Formats: sarif, json, html, junit, sonarqube, console, github, gitlab.',
    category: 'generation',
    estimatedTokens: '~500-5000',
    handler: async (p) => loadNapi().driftReport(p.format as string ?? 'json'),
  });

  // PH-TOOL-27: drift_gc — garbage collection with tiered retention
  register(catalog, {
    name: 'drift_gc',
    description: 'Run garbage collection on drift.db. Tiered retention: short (30d detections), medium (90d trends), long (365d caches). Returns deletion stats.',
    category: 'operational',
    estimatedTokens: '~100',
    handler: async (p) => loadNapi().driftGC(
      p.shortDays as number | undefined,
      p.mediumDays as number | undefined,
      p.longDays as number | undefined,
    ),
  });

  // ─── Bridge tools (12) — cortex-drift-bridge ────────────────────

  // BW-MCP-04: drift_bridge_status
  register(catalog, {
    name: 'drift_bridge_status',
    description: 'Bridge availability, license tier, grounding config.',
    category: 'discovery',
    estimatedTokens: '~200',
    handler: async () => loadNapi().driftBridgeStatus(),
  });

  // BW-MCP-05: drift_bridge_health
  register(catalog, {
    name: 'drift_bridge_health',
    description: 'Bridge health: per-subsystem availability (cortex_db, drift_db, bridge_db, causal_engine).',
    category: 'discovery',
    estimatedTokens: '~200',
    handler: async () => loadNapi().driftBridgeHealth(),
  });

  // BW-MCP-06: drift_bridge_ground
  register(catalog, {
    name: 'drift_bridge_ground',
    description: 'Ground a memory against drift.db evidence. Returns verdict, score, and evidence details.',
    category: 'analysis',
    estimatedTokens: '~400',
    handler: async (p) => loadNapi().driftBridgeGroundMemory(p.memoryId as string, p.memoryType as string),
  });

  // BW-MCP-07: drift_bridge_ground_all
  register(catalog, {
    name: 'drift_bridge_ground_all',
    description: 'Run full grounding loop on all bridge memories. Returns snapshot with validated/partial/weak/invalidated counts.',
    category: 'analysis',
    estimatedTokens: '~300',
    handler: async () => loadNapi().driftBridgeGroundAll(),
  });

  // drift_bridge_memories
  register(catalog, {
    name: 'drift_bridge_memories',
    description: 'List bridge memories with grounding verdicts. Supports type, limit, and verdict filters.',
    category: 'exploration',
    estimatedTokens: '~500',
    handler: async () => {
      const napi = loadNapi();
      const snapshot = napi.driftBridgeGroundAll();
      return {
        total_checked: snapshot.total_checked,
        validated: snapshot.validated,
        partial: snapshot.partial,
        weak: snapshot.weak,
        invalidated: snapshot.invalidated,
        avg_grounding_score: snapshot.avg_grounding_score,
      };
    },
  });

  // drift_bridge_grounding_history
  register(catalog, {
    name: 'drift_bridge_grounding_history',
    description: 'Grounding score history for a specific memory over time.',
    category: 'exploration',
    estimatedTokens: '~300',
    handler: async (p) => loadNapi().driftBridgeGroundingHistory(p.memoryId as string, p.limit as number | undefined),
  });

  // BW-MCP-08: drift_bridge_why
  register(catalog, {
    name: 'drift_bridge_why',
    description: 'Why does this pattern/violation/constraint exist? Causal explanation with grounding evidence.',
    category: 'analysis',
    estimatedTokens: '~600',
    handler: async (p) => loadNapi().driftBridgeExplainSpec(`${p.entityType as string}:${p.entityId as string}`),
  });

  // drift_bridge_counterfactual
  register(catalog, {
    name: 'drift_bridge_counterfactual',
    description: 'What if this memory didn\'t exist? Shows affected downstream memories and max causal depth.',
    category: 'analysis',
    estimatedTokens: '~400',
    handler: async (p) => loadNapi().driftBridgeCounterfactual(p.memoryId as string),
  });

  // drift_bridge_intervention
  register(catalog, {
    name: 'drift_bridge_intervention',
    description: 'If we change this memory, what breaks? Shows impacted count and propagation depth.',
    category: 'analysis',
    estimatedTokens: '~400',
    handler: async (p) => loadNapi().driftBridgeIntervention(p.memoryId as string),
  });

  // drift_bridge_narrative
  register(catalog, {
    name: 'drift_bridge_narrative',
    description: 'Full causal narrative with upstream origins and downstream effects. Renders as markdown.',
    category: 'analysis',
    estimatedTokens: '~800',
    handler: async (p) => loadNapi().driftBridgeUnifiedNarrative(p.memoryId as string),
  });

  // BW-MCP-09: drift_bridge_learn
  register(catalog, {
    name: 'drift_bridge_learn',
    description: 'Teach the system: create a correction memory for an entity. Adjusts future grounding.',
    category: 'feedback',
    estimatedTokens: '~100',
    handler: async (p) => loadNapi().driftBridgeSpecCorrection(JSON.stringify({
      entity_type: p.entityType as string,
      entity_id: p.entityId as string,
      correction: p.correction as string,
      category: (p.category as string) ?? 'general',
    })),
  });

  // drift_bridge_events
  register(catalog, {
    name: 'drift_bridge_events',
    description: 'List all 21 event→memory mappings with tier requirements and confidence/importance.',
    category: 'exploration',
    estimatedTokens: '~400',
    handler: async () => loadNapi().driftBridgeEventMappings(),
  });

  // ─── Cortex tools (40) ─────────────────────────────────────────
  // Only register if cortex is available (lazy — getCortex() throws if not init'd)
  try {
    registerCortexTools(catalog);
  } catch (err) {
    // Non-fatal — Cortex tools won't be available
    console.warn(
      '[drift-mcp] Cortex tool registration failed — Cortex tools will not be available.',
      err instanceof Error ? err.message : String(err),
    );
  }

  return catalog;
}

function register(catalog: Map<string, InternalTool>, tool: InternalTool): void {
  catalog.set(tool.name, tool);
}

function listCapabilities(catalog: Map<string, InternalTool>): {
  tools: Array<{ name: string; description: string; category: string; estimatedTokens: string }>;
  totalCount: number;
} {
  const tools = Array.from(catalog.values()).map((t) => ({
    name: t.name,
    description: t.description,
    category: t.category,
    estimatedTokens: t.estimatedTokens,
  }));
  return { tools, totalCount: tools.length };
}

/**
 * Execute drift_tool — dynamic dispatch to internal tool.
 *
 * When infrastructure is provided:
 * - Checks cache for read-only tools before executing
 * - Wraps execution with ErrorHandler for structured errors
 * - Applies ResponseBuilder token budgeting for large responses
 * - Invalidates cache after mutation tools
 */
export async function handleDriftTool(
  params: DriftToolParams,
  catalog: Map<string, InternalTool>,
  infra?: InfrastructureLayer,
): Promise<unknown> {
  const tool = catalog.get(params.tool);
  if (!tool) {
    const available = Array.from(catalog.keys()).join(', ');
    throw new Error(
      `Unknown tool: "${params.tool}". Available tools: ${available}`,
    );
  }

  const toolParams = params.params ?? {};

  // Cache check for read-only tools
  if (infra && (CACHEABLE_TOOLS.has(params.tool) || CORTEX_CACHEABLE_TOOLS.has(params.tool))) {
    const cacheKey = ResponseCache.buildKey(infra.projectRoot, params.tool, toolParams);
    const cached = infra.cache.get(cacheKey);
    if (cached !== undefined) return cached;
  }

  // Execute with error handling
  const result = await ErrorHandler.wrap(() => tool.handler(toolParams));

  // Invalidate cache after mutations
  if (infra && (MUTATION_TOOLS.has(params.tool) || CORTEX_MUTATION_TOOLS.has(params.tool))) {
    infra.cache.clear();
  }

  // Apply response builder for token budgeting on large object results
  let finalResult = result;
  if (infra && result && typeof result === 'object' && !isStructuredError(result)) {
    finalResult = infra.responseBuilder.build(
      result as Record<string, unknown>,
      `${params.tool} result`,
    );
  }

  // Cache write for read-only tools (cache the final wrapped result)
  if (infra && (CACHEABLE_TOOLS.has(params.tool) || CORTEX_CACHEABLE_TOOLS.has(params.tool)) && !isStructuredError(finalResult)) {
    const cacheKey = ResponseCache.buildKey(infra.projectRoot, params.tool, toolParams);
    const tokenEstimate = infra.tokenEstimator.estimateResponseTokens(params.tool, toolParams);
    infra.cache.set(cacheKey, finalResult, undefined, tokenEstimate);
  }

  return finalResult;
}

function isStructuredError(val: unknown): boolean {
  return !!val && typeof val === 'object' && 'code' in val && 'recoveryHints' in val;
}
