/**
 * drift_workflow — Composite workflow dispatch.
 *
 * 6th MCP entry point. Executes predefined multi-tool workflows:
 * - pre_commit: check → violations → impact
 * - security_audit: owasp → crypto → taint → error_handling
 * - code_review: status → context → violations → patterns
 * - health_check: status → audit → test_topology → dna
 * - onboard: status → conventions → patterns → contracts
 *
 * PH-TOOL-26
 */

import type { InternalTool } from '../types.js';

/** JSON Schema for drift_workflow parameters. */
export const DRIFT_WORKFLOW_SCHEMA = {
  type: 'object' as const,
  properties: {
    workflow: {
      type: 'string',
      description: 'Workflow name: pre_commit, security_audit, code_review, health_check, onboard, cortex_health_check, cortex_onboard, bridge_health_check',
    },
    path: {
      type: 'string',
      description: 'Project path (defaults to project root)',
    },
    options: {
      type: 'object',
      description: 'Workflow-specific options',
      additionalProperties: true,
    },
  },
  required: ['workflow'],
  additionalProperties: false,
};

export interface WorkflowParams {
  workflow: string;
  path?: string;
  options?: Record<string, unknown>;
}

export interface WorkflowStepResult {
  tool: string;
  success: boolean;
  durationMs: number;
  data?: unknown;
  error?: string;
}

export interface WorkflowResult {
  workflow: string;
  steps: WorkflowStepResult[];
  totalDurationMs: number;
  _workflow: {
    toolsRun: string[];
    durationPerTool: Record<string, number>;
    partialFailure: boolean;
  };
}

/** Workflow definitions: name → ordered list of internal tool names + params. */
const WORKFLOWS: Record<string, Array<{ tool: string; params: (path: string) => Record<string, unknown> }>> = {
  pre_commit: [
    { tool: 'drift_prevalidate', params: (p) => ({ path: p }) },
    { tool: 'drift_suggest_changes', params: (p) => ({ root: p }) },
    { tool: 'drift_impact_analysis', params: (p) => ({ root: p }) },
  ],
  security_audit: [
    { tool: 'drift_owasp', params: (p) => ({ root: p }) },
    { tool: 'drift_crypto', params: (p) => ({ root: p }) },
    { tool: 'drift_taint', params: (p) => ({ root: p }) },
    { tool: 'drift_error_handling', params: (p) => ({ root: p }) },
  ],
  code_review: [
    { tool: 'drift_status', params: () => ({}) },
    { tool: 'drift_explain', params: (p) => ({ query: 'code review', depth: 'standard', root: p }) },
    { tool: 'drift_suggest_changes', params: (p) => ({ root: p }) },
    { tool: 'drift_patterns_list', params: () => ({}) },
  ],
  health_check: [
    { tool: 'drift_status', params: () => ({}) },
    { tool: 'drift_audit', params: (p) => ({ root: p }) },
    { tool: 'drift_test_topology', params: (p) => ({ root: p }) },
    { tool: 'drift_dna_profile', params: (p) => ({ root: p }) },
  ],
  onboard: [
    { tool: 'drift_status', params: () => ({}) },
    { tool: 'drift_conventions', params: () => ({}) },
    { tool: 'drift_patterns_list', params: () => ({}) },
    { tool: 'drift_contracts', params: (p) => ({ root: p }) },
  ],
  cortex_health_check: [
    { tool: 'cortex_status', params: () => ({}) },
    { tool: 'cortex_validate_system', params: () => ({}) },
    { tool: 'cortex_knowledge_health', params: () => ({}) },
  ],
  cortex_onboard: [
    { tool: 'cortex_memory_add', params: () => ({ memory_type: 'episodic', content: { type: 'episodic', data: { interaction: 'First Cortex session', context: 'onboarding', outcome: null } }, summary: 'Cortex onboarding session started' }) },
    { tool: 'cortex_predict', params: () => ({}) },
    { tool: 'cortex_status', params: () => ({}) },
  ],
  bridge_health_check: [
    { tool: 'drift_bridge_status', params: () => ({}) },
    { tool: 'drift_bridge_health', params: () => ({}) },
    { tool: 'drift_bridge_ground_all', params: () => ({}) },
  ],
};

/** List of valid workflow names. */
export const VALID_WORKFLOWS = Object.keys(WORKFLOWS);

/**
 * Execute drift_workflow — composite workflow dispatch.
 * Partial failure: if one sub-tool fails, the rest still run.
 */
export async function handleDriftWorkflow(
  params: WorkflowParams,
  catalog: Map<string, InternalTool>,
): Promise<WorkflowResult> {
  const workflowDef = WORKFLOWS[params.workflow];
  if (!workflowDef) {
    throw new Error(
      `Unknown workflow: "${params.workflow}". Valid workflows: ${VALID_WORKFLOWS.join(', ')}`,
    );
  }

  const projectPath = params.path ?? '.';
  const steps: WorkflowStepResult[] = [];
  const durationPerTool: Record<string, number> = {};
  const toolsRun: string[] = [];
  let partialFailure = false;
  const overallStart = Date.now();

  for (const step of workflowDef) {
    const tool = catalog.get(step.tool);
    const stepStart = Date.now();
    toolsRun.push(step.tool);

    if (!tool) {
      steps.push({
        tool: step.tool,
        success: false,
        durationMs: 0,
        error: `Tool "${step.tool}" not found in catalog`,
      });
      partialFailure = true;
      continue;
    }

    try {
      const stepParams = step.params(projectPath);
      const data = await tool.handler(stepParams);
      const durationMs = Date.now() - stepStart;
      steps.push({ tool: step.tool, success: true, durationMs, data });
      durationPerTool[step.tool] = durationMs;
    } catch (error: unknown) {
      const durationMs = Date.now() - stepStart;
      const message = error instanceof Error ? error.message : String(error);
      steps.push({ tool: step.tool, success: false, durationMs, error: message });
      durationPerTool[step.tool] = durationMs;
      partialFailure = true;
    }
  }

  return {
    workflow: params.workflow,
    steps,
    totalDurationMs: Date.now() - overallStart,
    _workflow: {
      toolsRun,
      durationPerTool,
      partialFailure,
    },
  };
}
