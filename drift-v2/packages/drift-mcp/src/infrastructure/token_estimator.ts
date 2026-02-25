/**
 * TokenEstimator — heuristic token estimation for response budgeting.
 *
 * - English text: chars / 3.5
 * - Code: chars / 2.5
 * - Per-tool historical averages when available
 * - Budget checking for response truncation
 *
 * PH-INFRA-04
 */

export interface TokenEstimatorConfig {
  englishCharsPerToken: number;
  codeCharsPerToken: number;
}

const DEFAULT_TOKEN_ESTIMATOR_CONFIG: TokenEstimatorConfig = {
  englishCharsPerToken: 3.5,
  codeCharsPerToken: 2.5,
};

/** Per-tool historical average token estimates. Updated as we gather data. */
const TOOL_AVERAGES: Record<string, number> = {
  drift_status: 200,
  drift_context: 2000,
  drift_scan: 300,
  drift_check: 400,
  drift_violations: 800,
  drift_audit: 500,
  drift_patterns: 600,
  drift_coupling_analysis: 700,
  drift_owasp_analysis: 900,
  drift_taint_analysis: 600,
  drift_impact_analysis: 500,
  drift_test_topology: 400,
  drift_dna_analysis: 600,
  drift_decomposition: 800,
};

export class TokenEstimator {
  private readonly config: TokenEstimatorConfig;

  constructor(config: Partial<TokenEstimatorConfig> = {}) {
    this.config = { ...DEFAULT_TOKEN_ESTIMATOR_CONFIG, ...config };
  }

  /** Estimate tokens for a text string. */
  estimateTokens(text: string): number {
    if (!text || text.length === 0) return 0;

    // Heuristic: use code ratio if text contains code-like characters
    const codeIndicators = /[{}();=><[\]]/g;
    const matches = text.match(codeIndicators);
    const codeRatio = matches ? Math.min(matches.length / text.length * 10, 1) : 0;

    const charsPerToken =
      this.config.englishCharsPerToken * (1 - codeRatio) +
      this.config.codeCharsPerToken * codeRatio;

    return Math.ceil(text.length / charsPerToken);
  }

  /** Estimate response tokens for a tool, using historical averages if available. */
  estimateResponseTokens(toolName: string, _params?: Record<string, unknown>): number {
    const average = TOOL_AVERAGES[toolName];
    if (average !== undefined) {
      return average;
    }
    // Default estimate for unknown tools
    return 500;
  }

  /** Check if a tool response would exceed the token budget. */
  wouldExceedBudget(
    toolName: string,
    params: Record<string, unknown> | undefined,
    budget: number,
  ): boolean {
    return this.estimateResponseTokens(toolName, params) > budget;
  }
}
