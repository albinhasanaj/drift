/**
 * Tool registration — registers all MCP tools on the server.
 *
 * Progressive disclosure architecture:
 * - 6 registered MCP entry points: drift_status, drift_context, drift_scan, drift_tool, drift_discover, drift_workflow
 * - ~41 internal tools accessible via drift_tool dynamic dispatch
 * - Reduces token overhead ~85% compared to registering all tools individually
 */

import { z } from 'zod';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { handleDriftStatus } from './drift_status.js';
import { handleDriftContext } from './drift_context.js';
import { handleDriftScan } from './drift_scan.js';
import {
  handleDriftTool,
  buildToolCatalog,
} from './drift_tool.js';
import { handleDriftDiscover } from './drift_discover.js';
import { handleDriftWorkflow } from './drift_workflow.js';
import type { InternalTool } from '../types.js';
import type { InfrastructureLayer } from '../infrastructure/index.js';
import { ErrorHandler } from '../infrastructure/error_handler.js';

/**
 * Register all MCP tools on the server instance.
 * Returns the internal tool catalog for drift_tool dispatch.
 */
export function registerTools(server: McpServer, infra?: InfrastructureLayer): Map<string, InternalTool> {
  const catalog = buildToolCatalog();

  // Entry point 1: drift_status — overview, <1ms
  server.tool(
    'drift_status',
    'Get project overview — file count, pattern count, violations, health score, gate status. Reads materialized view for <1ms response.',
    {},
    async () => {
      if (infra) {
        const rl = infra.rateLimiter.check('drift_status');
        if (!rl.allowed) return { content: [{ type: 'text' as const, text: JSON.stringify({ error: rl.reason, retryAfterMs: rl.retryAfterMs }) }] };
      }
      const result = await ErrorHandler.wrap(() => handleDriftStatus());
      const text = infra
        ? JSON.stringify(infra.responseBuilder.build(result as unknown as Record<string, unknown>, 'Project health overview'), null, 2)
        : JSON.stringify(result, null, 2);
      return { content: [{ type: 'text' as const, text }] };
    },
  );

  // Entry point 2: drift_context — intent-weighted deep dive
  server.tool(
    'drift_context',
    'Get intent-weighted context for your current task. Replaces 3-5 individual tool calls with a single curated response. Supports shallow/standard/deep depth levels.',
    { intent: z.string(), depth: z.string().optional(), dataJson: z.string().optional() },
    async (params) => {
      if (infra) {
        const rl = infra.rateLimiter.check('drift_context');
        if (!rl.allowed) return { content: [{ type: 'text' as const, text: JSON.stringify({ error: rl.reason, retryAfterMs: rl.retryAfterMs }) }] };
      }
      const result = await ErrorHandler.wrap(() => handleDriftContext(params as Parameters<typeof handleDriftContext>[0]));
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Entry point 3: drift_scan — trigger analysis
  server.tool(
    'drift_scan',
    'Trigger analysis on the project. Scans files, detects patterns, identifies violations. Supports incremental mode for faster re-scans.',
    { path: z.string().optional(), forceFull: z.boolean().optional() },
    async (params) => {
      if (infra) {
        const rl = infra.rateLimiter.check('drift_scan');
        if (!rl.allowed) return { content: [{ type: 'text' as const, text: JSON.stringify({ error: rl.reason, retryAfterMs: rl.retryAfterMs }) }] };
      }
      const result = await ErrorHandler.wrap(() => handleDriftScan(params as Parameters<typeof handleDriftScan>[0]));
      // Invalidate cache after mutation (scan populates DB)
      if (infra) infra.cache.clear();
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Entry point 4: drift_tool — dynamic dispatch for ~41 internal tools
  server.tool(
    'drift_tool',
    'Access any of ~41 internal analysis tools by name. Use drift_discover to find relevant tools. Supports: reachability, taint, impact, coupling, test_topology, error_handling, patterns, security, audit, simulate, decisions, and more.',
    { tool: z.string(), params: z.record(z.string(), z.unknown()).optional() },
    async (params) => {
      const toolParams = params as unknown as Parameters<typeof handleDriftTool>[0];
      if (infra) {
        const rl = infra.rateLimiter.check(toolParams.tool);
        if (!rl.allowed) return { content: [{ type: 'text' as const, text: JSON.stringify({ error: rl.reason, retryAfterMs: rl.retryAfterMs }) }] };
      }
      const result = await handleDriftTool(toolParams, catalog, infra);
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Entry point 5: drift_discover — intent-guided tool recommendation
  server.tool(
    'drift_discover',
    'Find the most relevant tools for your intent. Scores tools by keyword match, returns top N ranked by relevance. Use before drift_tool to find the right tool.',
    { intent: z.string(), focus: z.string().optional(), maxTools: z.number().optional() },
    async (params) => {
      if (infra) {
        const rl = infra.rateLimiter.check('drift_discover');
        if (!rl.allowed) return { content: [{ type: 'text' as const, text: JSON.stringify({ error: rl.reason, retryAfterMs: rl.retryAfterMs }) }] };
      }
      const result = handleDriftDiscover(
        params as Parameters<typeof handleDriftDiscover>[0],
        catalog,
      );
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  // Entry point 6: drift_workflow — composite workflow dispatch
  server.tool(
    'drift_workflow',
    'Run a predefined multi-tool workflow. Available: pre_commit, security_audit, code_review, health_check, onboard. Each executes 3-4 tools in sequence with partial failure handling.',
    { workflow: z.string(), path: z.string().optional(), options: z.record(z.string(), z.unknown()).optional() },
    async (params) => {
      if (infra) {
        const rl = infra.rateLimiter.check('drift_workflow');
        if (!rl.allowed) return { content: [{ type: 'text' as const, text: JSON.stringify({ error: rl.reason, retryAfterMs: rl.retryAfterMs }) }] };
      }
      const result = await ErrorHandler.wrap(() => handleDriftWorkflow(
        params as Parameters<typeof handleDriftWorkflow>[0],
        catalog,
      ));
      return { content: [{ type: 'text' as const, text: JSON.stringify(result, null, 2) }] };
    },
  );

  return catalog;
}

export { handleDriftStatus } from './drift_status.js';
export { handleDriftContext } from './drift_context.js';
export { handleDriftScan } from './drift_scan.js';
export { handleDriftTool, buildToolCatalog } from './drift_tool.js';
export { handleDriftDiscover } from './drift_discover.js';
export { handleDriftWorkflow } from './drift_workflow.js';
