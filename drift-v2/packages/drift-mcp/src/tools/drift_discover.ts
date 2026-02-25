/**
 * drift_discover — Intent-guided tool recommendation.
 *
 * 5th MCP entry point. Scores catalog tools by keyword match to
 * description + category, applies ToolFilter, returns top N ranked
 * by relevance.
 *
 * PH-TOOL-25
 */

import type { InternalTool } from '../types.js';

/** JSON Schema for drift_discover parameters. */
export const DRIFT_DISCOVER_SCHEMA = {
  type: 'object' as const,
  properties: {
    intent: {
      type: 'string',
      description: 'What you are trying to accomplish (e.g., "security audit", "fix bug", "understand code")',
    },
    focus: {
      type: 'string',
      description: 'Optional focus area to boost relevant tools (e.g., "auth", "database")',
    },
    maxTools: {
      type: 'number',
      description: 'Maximum number of tools to return (default 5)',
      default: 5,
    },
  },
  required: ['intent'],
  additionalProperties: false,
};

export interface DiscoverParams {
  intent: string;
  focus?: string;
  maxTools?: number;
}

export interface DiscoveredTool {
  name: string;
  description: string;
  category: string;
  estimatedTokens: string;
  relevanceScore: number;
}

export interface DiscoverResult {
  intent: string;
  tools: DiscoveredTool[];
  totalAvailable: number;
}

/** Intent → keyword associations for tool scoring. */
const INTENT_KEYWORDS: Record<string, string[]> = {
  security: ['owasp', 'crypto', 'taint', 'security', 'vulnerability', 'cwe', 'error_handling', 'cortex_privacy', 'sanitize'],
  audit: ['owasp', 'crypto', 'taint', 'audit', 'check', 'violations', 'security', 'compliance'],
  bug: ['violations', 'impact', 'explain', 'context', 'taint', 'error', 'check', 'cortex_why'],
  fix: ['violations', 'impact', 'explain', 'check', 'prevalidate', 'suggest'],
  understand: ['context', 'patterns', 'conventions', 'dna', 'coupling', 'explain', 'cortex_why', 'cortex_explain', 'cortex_related'],
  review: ['status', 'context', 'violations', 'patterns', 'check', 'audit', 'cortex_status'],
  refactor: ['coupling', 'decomposition', 'dna', 'patterns', 'impact', 'constraints'],
  onboard: ['status', 'conventions', 'patterns', 'contracts', 'context', 'cortex_status', 'cortex_search'],
  test: ['test_topology', 'coverage', 'impact', 'check'],
  commit: ['check', 'violations', 'impact', 'prevalidate', 'quality_gate'],
  performance: ['coupling', 'decomposition', 'impact', 'constants'],
  memory: ['cortex_memory', 'cortex_search', 'cortex_context', 'cortex_learn', 'cortex_feedback', 'cortex_export', 'cortex_import', 'cortex_validate', 'bridge_status', 'bridge_memories', 'bridge_ground', 'bridge_events'],
  agent: ['cortex_agent', 'cortex_agent_register', 'cortex_agent_share', 'cortex_agent_trust', 'cortex_agent_provenance', 'cortex_agent_project'],
  cortex: ['cortex_status', 'cortex_metrics', 'cortex_search', 'cortex_memory', 'cortex_learn', 'cortex_consolidate', 'cortex_gc', 'cortex_validate'],
  knowledge: ['cortex_knowledge', 'cortex_time', 'cortex_search', 'cortex_why', 'cortex_explain', 'cortex_related'],
  temporal: ['cortex_time_travel', 'cortex_time_diff', 'cortex_time_replay', 'cortex_knowledge_health', 'cortex_knowledge_timeline'],
  predict: ['cortex_predict', 'cortex_preload', 'cortex_gen_context'],
  consolidate: ['cortex_consolidate', 'cortex_gc', 'cortex_reembed', 'cortex_validate_system'],
  // Bridge-specific intents
  grounding: ['bridge_ground', 'bridge_ground_all', 'bridge_memories', 'bridge_grounding_history', 'bridge_status', 'bridge_health'],
  why: ['bridge_why', 'bridge_narrative', 'bridge_counterfactual', 'bridge_intervention', 'cortex_why', 'cortex_explain'],
  causal: ['bridge_why', 'bridge_narrative', 'bridge_counterfactual', 'bridge_intervention', 'cortex_causal', 'cortex_related'],
  learn: ['bridge_learn', 'cortex_learn', 'cortex_feedback', 'bridge_events'],
  teach: ['bridge_learn', 'cortex_learn', 'cortex_feedback', 'bridge_events'],
  bridge: ['bridge_status', 'bridge_health', 'bridge_ground', 'bridge_ground_all', 'bridge_memories', 'bridge_why', 'bridge_learn', 'bridge_events', 'bridge_narrative'],
};

/**
 * Execute drift_discover — intent-guided tool recommendation.
 */
export function handleDriftDiscover(
  params: DiscoverParams,
  catalog: Map<string, InternalTool>,
): DiscoverResult {
  const maxTools = params.maxTools ?? 5;

  if (maxTools <= 0) {
    return { intent: params.intent, tools: [], totalAvailable: catalog.size };
  }

  const intentLower = params.intent.toLowerCase();
  const focusLower = params.focus?.toLowerCase();

  // Find matching intent keywords
  const matchedKeywords = new Set<string>();
  for (const [key, keywords] of Object.entries(INTENT_KEYWORDS)) {
    if (intentLower.includes(key)) {
      for (const kw of keywords) {
        matchedKeywords.add(kw);
      }
    }
  }

  // Also treat individual words in intent as keywords
  for (const word of intentLower.split(/\s+/)) {
    if (word.length > 2) matchedKeywords.add(word);
  }

  // Score each tool
  const scored: DiscoveredTool[] = [];
  for (const [, tool] of catalog) {
    let score = 0;
    const nameLower = tool.name.toLowerCase();
    const descLower = tool.description.toLowerCase();

    // Keyword match scoring
    for (const kw of matchedKeywords) {
      if (nameLower.includes(kw)) score += 3;
      if (descLower.includes(kw)) score += 1;
    }

    // Focus boost
    if (focusLower) {
      if (nameLower.includes(focusLower)) score += 2;
      if (descLower.includes(focusLower)) score += 1;
    }

    // Base score for all tools (so unknown intents still return something)
    score += 0.1;

    scored.push({
      name: tool.name,
      description: tool.description,
      category: tool.category,
      estimatedTokens: tool.estimatedTokens,
      relevanceScore: Math.round(score * 100) / 100,
    });
  }

  // Sort by relevance descending
  scored.sort((a, b) => b.relevanceScore - a.relevanceScore);

  return {
    intent: params.intent,
    tools: scored.slice(0, maxTools),
    totalAvailable: catalog.size,
  };
}
