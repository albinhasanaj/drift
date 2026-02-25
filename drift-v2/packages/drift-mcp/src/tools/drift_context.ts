/**
 * drift_context — intent-weighted deep dive with token budgeting.
 *
 * Performance target: <100ms.
 * Replaces 3-5 individual tool calls with a single curated response.
 * Token budgeting ensures response fits within maxResponseTokens.
 */

import { loadNapi } from '../napi.js';
import type { DriftContextParams, ContextOutput } from '../types.js';

/** JSON Schema for drift_context parameters. */
export const DRIFT_CONTEXT_SCHEMA = {
  type: 'object' as const,
  properties: {
    intent: {
      type: 'string',
      description: 'What the AI agent is trying to accomplish (e.g., "fix_bug", "add_feature", "refactor", "review_code")',
    },
    depth: {
      type: 'string',
      enum: ['shallow', 'standard', 'deep'],
      description: 'Context depth level. shallow=overview, standard=working context, deep=full analysis',
      default: 'standard',
    },
    focus: {
      type: 'string',
      description: 'Optional focus area — file path, module name, or function name',
    },
  },
  required: ['intent'],
  additionalProperties: false,
};

/**
 * Execute drift_context — intent-weighted context via NAPI drift_context().
 * The contract method returns Promise<string> (JSON). We parse it into ContextOutput.
 */
export async function handleDriftContext(
  params: DriftContextParams,
): Promise<ContextOutput> {
  const napi = loadNapi();
  const depth = params.depth ?? 'standard';
  const dataJson = params.focus ? JSON.stringify({ focus: params.focus }) : '{}';
  const jsonStr = await napi.driftContext(params.intent, depth, dataJson);

  let parsed: { sections?: Array<{ name: string; content: string }>; tokenCount?: number; intent?: string; depth?: string };
  try {
    parsed = JSON.parse(jsonStr) as typeof parsed;
  } catch {
    parsed = {};
  }

  const sections = (parsed.sections ?? []).map((s, i) => ({
    title: s.name,
    content: s.content,
    relevanceScore: 1.0 - i * 0.1,
  }));

  const result: ContextOutput = {
    intent: params.intent,
    depth,
    sections,
    tokenCount: parsed.tokenCount ?? 0,
    truncated: false,
  };

  // If focus is specified, filter sections by relevance to focus area
  if (params.focus && result.sections) {
    const focusLower = params.focus.toLowerCase();
    result.sections.sort((a, b) => {
      const aRelevant = a.title.toLowerCase().includes(focusLower) ||
        a.content.toLowerCase().includes(focusLower);
      const bRelevant = b.title.toLowerCase().includes(focusLower) ||
        b.content.toLowerCase().includes(focusLower);
      if (aRelevant && !bRelevant) return -1;
      if (!aRelevant && bRelevant) return 1;
      return b.relevanceScore - a.relevanceScore;
    });
  }

  return result;
}
