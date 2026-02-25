/**
 * Shared types for the Drift MCP server.
 */

/** MCP server configuration. */
export interface McpConfig {
  /** Maximum tokens in a single response (default 8000). */
  maxResponseTokens: number;
  /** Transport mode. */
  transport: 'stdio' | 'http';
  /** HTTP port (for HTTP transport). */
  port?: number;
  /** Project root path. */
  projectRoot?: string;
  /** Enable Cortex memory system integration (default true). */
  cortexEnabled?: boolean;
  /** Path to Cortex SQLite database (default '.cortex/cortex.db'). */
  cortexDbPath?: string;
}

export const DEFAULT_MCP_CONFIG: McpConfig = {
  maxResponseTokens: 8000,
  transport: 'stdio',
  cortexEnabled: true,
  cortexDbPath: '.cortex/cortex.db',
};

/** Parameters for drift_tool dynamic dispatch. */
export interface DriftToolParams {
  /** Internal tool name (e.g., "reachability", "taint", "impact"). */
  tool: string;
  /** Tool-specific parameters. */
  params: Record<string, unknown>;
}

/** Parameters for drift_context. */
export interface DriftContextParams {
  /** Intent describing what the AI agent is trying to do. */
  intent: string;
  /** Depth level: "shallow", "standard", or "deep". */
  depth?: 'shallow' | 'standard' | 'deep';
  /** Optional focus area (file path, module name, etc.). */
  focus?: string;
}

/** Parameters for drift_scan. */
export interface DriftScanParams {
  /** Path to scan (defaults to project root). */
  path?: string;
  /** Whether to run incrementally. */
  incremental?: boolean;
}

/** Status overview returned by drift_status. */
export interface StatusOverview {
  version: string;
  projectRoot: string;
  fileCount: number;
  patternCount: number;
  violationCount: number;
  healthScore: number;
  lastScanTime: string | null;
  gateStatus: 'passed' | 'failed' | 'unknown';
}

/** Context output from drift_context. */
export interface ContextOutput {
  intent: string;
  depth: string;
  sections: ContextSection[];
  tokenCount: number;
  truncated: boolean;
}

export interface ContextSection {
  title: string;
  content: string;
  relevanceScore: number;
}

/** Scan result from drift_scan. */
export interface ScanResult {
  filesScanned: number;
  patternsDetected: number;
  violationsFound: number;
  durationMs: number;
}

/** Internal tool catalog entry. */
export interface InternalTool {
  name: string;
  description: string;
  category: string;
  estimatedTokens: string;
  handler: (params: Record<string, unknown>) => Promise<unknown>;
}
