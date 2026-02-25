/**
 * ErrorHandler — maps NAPI error codes to structured MCP errors with recovery hints.
 *
 * Every error includes: code, message, recoveryHints[], alternativeTools[], retryable, retryAfterMs.
 * Wraps tool execution to catch and transform errors before they reach the MCP transport.
 *
 * PH-INFRA-05
 */

export interface StructuredError {
  code: string;
  message: string;
  recoveryHints: string[];
  alternativeTools: string[];
  retryable: boolean;
  retryAfterMs?: number;
  stack?: string;
}

interface ErrorMapping {
  code: string;
  recoveryHints: string[];
  alternativeTools: string[];
  retryable: boolean;
  retryAfterMs?: number;
}

const ERROR_MAPPINGS: Record<string, ErrorMapping> = {
  SCAN_ERROR: {
    code: 'SCAN_ERROR',
    recoveryHints: ['Run drift setup first', 'Ensure the project root exists', 'Check file permissions'],
    alternativeTools: ['drift_status'],
    retryable: false,
  },
  DB_BUSY: {
    code: 'DB_BUSY',
    recoveryHints: ['Wait for the current operation to complete', 'Try again shortly'],
    alternativeTools: [],
    retryable: true,
    retryAfterMs: 1000,
  },
  STORAGE_ERROR: {
    code: 'STORAGE_ERROR',
    recoveryHints: ['Check disk space', 'Verify drift.db is not corrupted', 'Run drift setup to re-initialize'],
    alternativeTools: [],
    retryable: false,
  },
  INIT_ERROR: {
    code: 'INIT_ERROR',
    recoveryHints: ['Run driftInitialize() first', 'Check project root path'],
    alternativeTools: ['drift_status'],
    retryable: false,
  },
  RUNTIME_NOT_INITIALIZED: {
    code: 'RUNTIME_NOT_INITIALIZED',
    recoveryHints: ['Call driftInitialize() before using analysis tools', 'Run drift setup'],
    alternativeTools: ['drift_status'],
    retryable: false,
  },
  ALREADY_INITIALIZED: {
    code: 'ALREADY_INITIALIZED',
    recoveryHints: ['Runtime is already initialized — this is usually safe to ignore'],
    alternativeTools: [],
    retryable: false,
  },
  CONFIG_ERROR: {
    code: 'CONFIG_ERROR',
    recoveryHints: ['Check drift.toml syntax', 'Use default configuration'],
    alternativeTools: [],
    retryable: false,
  },
  UNSUPPORTED_LANGUAGE: {
    code: 'UNSUPPORTED_LANGUAGE',
    recoveryHints: ['Check supported languages with drift_status', 'File may be in an unsupported language'],
    alternativeTools: [],
    retryable: false,
  },
  CANCELLED: {
    code: 'CANCELLED',
    recoveryHints: ['Operation was cancelled — retry if needed'],
    alternativeTools: [],
    retryable: true,
  },
  PARSE_ERROR: {
    code: 'PARSE_ERROR',
    recoveryHints: ['File may have syntax errors', 'Check file encoding'],
    alternativeTools: ['drift_status'],
    retryable: false,
  },
  GRAPH_ERROR: {
    code: 'GRAPH_ERROR',
    recoveryHints: ['Run drift_scan first to build the call graph', 'Graph may not be available for this language'],
    alternativeTools: ['drift_analyze'],
    retryable: false,
  },
  PATTERN_ERROR: {
    code: 'PATTERN_ERROR',
    recoveryHints: ['Pattern database may need rebuilding', 'Run drift_scan first'],
    alternativeTools: ['drift_check'],
    retryable: false,
  },
  TIMEOUT: {
    code: 'TIMEOUT',
    recoveryHints: ['Operation timed out — try a smaller scope', 'Use incremental mode'],
    alternativeTools: [],
    retryable: true,
    retryAfterMs: 5000,
  },
  UNKNOWN: {
    code: 'UNKNOWN',
    recoveryHints: ['An unexpected error occurred', 'Check server logs for details'],
    alternativeTools: ['drift_status'],
    retryable: false,
  },
};

export class ErrorHandler {
  /** Extract an error code from an error message. NAPI errors use `[CODE]` prefix. */
  static extractCode(error: unknown): string {
    const message = ErrorHandler.extractMessage(error);
    const match = message.match(/^\[([A-Z_]+)\]/);
    return match ? match[1]! : 'UNKNOWN';
  }

  /** Extract a human-readable message from any error type. */
  static extractMessage(error: unknown): string {
    if (error instanceof Error) return error.message;
    if (typeof error === 'string') return error;
    if (error === null) return 'null error';
    if (error === undefined) return 'undefined error';
    return String(error);
  }

  /** Map an error to a structured MCP error with recovery hints. */
  static toStructuredError(error: unknown): StructuredError {
    const code = ErrorHandler.extractCode(error);
    const mapping = ERROR_MAPPINGS[code] ?? ERROR_MAPPINGS['UNKNOWN']!;
    const message = ErrorHandler.extractMessage(error);

    return {
      code: mapping.code,
      message,
      recoveryHints: mapping.recoveryHints,
      alternativeTools: mapping.alternativeTools,
      retryable: mapping.retryable,
      retryAfterMs: mapping.retryAfterMs,
      stack: error instanceof Error ? error.stack : undefined,
    };
  }

  /**
   * Wrap a tool handler with error handling.
   * Catches any error and returns a structured error response.
   */
  static async wrap<T>(fn: () => Promise<T>): Promise<T | StructuredError> {
    try {
      return await fn();
    } catch (error: unknown) {
      return ErrorHandler.toStructuredError(error);
    }
  }
}
