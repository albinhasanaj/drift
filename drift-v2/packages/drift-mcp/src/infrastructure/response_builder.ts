/**
 * ResponseBuilder — summary-first response formatting with token budget enforcement.
 *
 * - Always adds _summary, _tokenEstimate
 * - If response exceeds token budget: truncate arrays, set _truncated: true, _totalCount
 * - Self-describing: agent always knows if data was cut
 *
 * PH-INFRA-07
 */

import { TokenEstimator } from './token_estimator.js';

export interface ResponseMetadata {
  _summary: string;
  _tokenEstimate: number;
  _truncated?: boolean;
  _totalCount?: number;
}

export interface BuilderConfig {
  defaultBudget: number;
}

const DEFAULT_BUILDER_CONFIG: BuilderConfig = {
  defaultBudget: 8000,
};

export class ResponseBuilder {
  private readonly estimator: TokenEstimator;
  private readonly config: BuilderConfig;

  constructor(estimator: TokenEstimator, config: Partial<BuilderConfig> = {}) {
    this.estimator = estimator;
    this.config = { ...DEFAULT_BUILDER_CONFIG, ...config };
  }

  /**
   * Build a response with token budget enforcement.
   * If the response exceeds the budget, arrays are truncated from the end.
   */
  build<T extends Record<string, unknown>>(
    data: T,
    summary: string,
    budget?: number,
  ): T & ResponseMetadata {
    const effectiveBudget = budget ?? this.config.defaultBudget;

    // First pass: estimate full response size
    const fullJson = JSON.stringify(data);
    const fullEstimate = this.estimator.estimateTokens(fullJson);

    if (fullEstimate <= effectiveBudget) {
      return {
        ...data,
        _summary: summary,
        _tokenEstimate: fullEstimate,
      };
    }

    // Over budget — truncate arrays
    const truncated = this.truncateArrays(data, effectiveBudget);
    const truncatedJson = JSON.stringify(truncated.data);
    const truncatedEstimate = this.estimator.estimateTokens(truncatedJson);

    return {
      ...truncated.data as T,
      _summary: summary,
      _tokenEstimate: truncatedEstimate,
      _truncated: true,
      _totalCount: truncated.totalCount,
    };
  }

  private truncateArrays<T extends Record<string, unknown>>(
    data: T,
    budget: number,
  ): { data: Record<string, unknown>; totalCount: number } {
    const result: Record<string, unknown> = {};
    let totalCount = 0;

    for (const [key, value] of Object.entries(data)) {
      if (Array.isArray(value)) {
        totalCount += value.length;
        // Binary search for the right truncation point
        let lo = 0;
        let hi = value.length;
        while (lo < hi) {
          const mid = Math.floor((lo + hi + 1) / 2);
          const candidate = { ...data, [key]: value.slice(0, mid) };
          const estimate = this.estimator.estimateTokens(JSON.stringify(candidate));
          if (estimate <= budget) {
            lo = mid;
          } else {
            hi = mid - 1;
          }
        }
        result[key] = value.slice(0, lo);
      } else {
        result[key] = value;
      }
    }

    return { data: result, totalCount };
  }
}
