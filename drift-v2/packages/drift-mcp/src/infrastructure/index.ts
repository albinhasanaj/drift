/**
 * Infrastructure Layer — barrel exports + InfrastructureLayer composition class.
 *
 * Composes all 7 infrastructure modules into a single ctx object
 * that tool handlers receive.
 *
 * PH-INFRA-01
 */

export { ResponseCache } from './cache.js';
export type { CacheEntry, CacheConfig } from './cache.js';

export { RateLimiter } from './rate_limiter.js';
export type { RateLimitResult, RateLimiterConfig } from './rate_limiter.js';

export { TokenEstimator } from './token_estimator.js';
export type { TokenEstimatorConfig } from './token_estimator.js';

export { ErrorHandler } from './error_handler.js';
export type { StructuredError } from './error_handler.js';

export { CursorManager } from './cursor_manager.js';
export type { CursorData, CursorConfig } from './cursor_manager.js';

export { ResponseBuilder } from './response_builder.js';
export type { ResponseMetadata, BuilderConfig } from './response_builder.js';

export { ToolFilter } from './tool_filter.js';
export type { InternalToolEntry } from './tool_filter.js';

import { ResponseCache } from './cache.js';
import { RateLimiter } from './rate_limiter.js';
import { TokenEstimator } from './token_estimator.js';
import { ErrorHandler } from './error_handler.js';
import { CursorManager } from './cursor_manager.js';
import { ResponseBuilder } from './response_builder.js';
import { ToolFilter } from './tool_filter.js';

export interface InfrastructureConfig {
  projectRoot?: string;
  maxResponseTokens?: number;
  cursorSecret?: string;
}

/**
 * InfrastructureLayer — composes all infrastructure modules into a unified ctx.
 *
 * Created once in server.ts, passed to all tool handlers.
 */
export class InfrastructureLayer {
  public readonly cache: ResponseCache;
  public readonly rateLimiter: RateLimiter;
  public readonly tokenEstimator: TokenEstimator;
  public readonly errorHandler: typeof ErrorHandler;
  public readonly cursorManager: CursorManager;
  public readonly responseBuilder: ResponseBuilder;
  public readonly toolFilter: ToolFilter;
  public readonly projectRoot: string;

  constructor(config: InfrastructureConfig = {}) {
    this.projectRoot = config.projectRoot ?? process.cwd();
    this.cache = new ResponseCache();
    this.rateLimiter = new RateLimiter();
    this.tokenEstimator = new TokenEstimator();
    this.errorHandler = ErrorHandler;
    this.cursorManager = new CursorManager(
      config.cursorSecret ? { secret: config.cursorSecret } : {},
    );
    this.responseBuilder = new ResponseBuilder(
      this.tokenEstimator,
      config.maxResponseTokens ? { defaultBudget: config.maxResponseTokens } : {},
    );
    this.toolFilter = new ToolFilter();
  }
}
