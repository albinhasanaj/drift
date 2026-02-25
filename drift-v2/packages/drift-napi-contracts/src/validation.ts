/**
 * Runtime parameter validators for NAPI functions.
 *
 * Run BEFORE the NAPI call to prevent Rust panics from bad JS input.
 * Returns { valid: true } or { valid: false, error, field }.
 */

export interface ValidationResult {
  valid: boolean;
  error?: string;
  field?: string;
}

const VALID: ValidationResult = { valid: true };

function invalid(field: string, error: string): ValidationResult {
  return { valid: false, error, field };
}

// ─── Scan Params ─────────────────────────────────────────────────────

export interface ScanValidationInput {
  root?: string;
  options?: {
    forceFull?: boolean;
    maxFileSize?: number;
    extraIgnore?: string[];
    followSymlinks?: boolean;
  };
}

export function validateScanParams(params: ScanValidationInput): ValidationResult {
  if (params.root !== undefined && params.root !== null) {
    if (typeof params.root !== 'string') {
      return invalid('root', 'root must be a string');
    }
    if (params.root.length === 0) {
      return invalid('root', 'root must not be empty');
    }
  }
  if (params.options !== undefined && params.options !== null) {
    if (typeof params.options !== 'object') {
      return invalid('options', 'options must be an object');
    }
    if (
      params.options.maxFileSize !== undefined &&
      (typeof params.options.maxFileSize !== 'number' || params.options.maxFileSize < 0)
    ) {
      return invalid('options.maxFileSize', 'maxFileSize must be a non-negative number');
    }
  }
  return VALID;
}

// ─── Context Params ──────────────────────────────────────────────────

const VALID_INTENTS = [
  'fix_bug',
  'add_feature',
  'understand_code',
  'understand',
  'security_audit',
  'generate_spec',
] as const;

const VALID_DEPTHS = ['overview', 'standard', 'deep'] as const;

export interface ContextValidationInput {
  intent?: string;
  depth?: string;
  dataJson?: string;
}

export function validateContextParams(params: ContextValidationInput): ValidationResult {
  if (params.intent === undefined || params.intent === null) {
    return invalid('intent', 'intent is required');
  }
  if (typeof params.intent !== 'string' || params.intent.length === 0) {
    return invalid('intent', 'intent must be a non-empty string');
  }
  if (!VALID_INTENTS.includes(params.intent as typeof VALID_INTENTS[number])) {
    return invalid(
      'intent',
      `intent must be one of: ${VALID_INTENTS.join(', ')}`,
    );
  }
  if (params.depth !== undefined && params.depth !== null) {
    if (!VALID_DEPTHS.includes(params.depth as typeof VALID_DEPTHS[number])) {
      return invalid(
        'depth',
        `depth must be one of: ${VALID_DEPTHS.join(', ')}`,
      );
    }
  }
  return VALID;
}

// ─── Simulate Params ─────────────────────────────────────────────────

const VALID_CATEGORIES = [
  'add_feature',
  'fix_bug',
  'refactor',
  'migrate_framework',
  'add_test',
  'security_fix',
  'performance_optimization',
  'dependency_update',
  'api_change',
  'database_migration',
  'config_change',
  'documentation',
  'infrastructure',
] as const;

export interface SimulateValidationInput {
  category?: string;
  description?: string;
  contextJson?: string;
}

export function validateSimulateParams(params: SimulateValidationInput): ValidationResult {
  if (params.category === undefined || params.category === null) {
    return invalid('category', 'category is required');
  }
  if (typeof params.category !== 'string' || params.category.length === 0) {
    return invalid('category', 'category must be a non-empty string');
  }
  if (!VALID_CATEGORIES.includes(params.category as typeof VALID_CATEGORIES[number])) {
    return invalid(
      'category',
      `category must be one of: ${VALID_CATEGORIES.join(', ')}`,
    );
  }
  if (params.description === undefined || params.description === null) {
    return invalid('description', 'description is required');
  }
  if (typeof params.description !== 'string' || params.description.length === 0) {
    return invalid('description', 'description must be a non-empty string');
  }
  return VALID;
}

// ─── Reachability Params ─────────────────────────────────────────────

export interface ReachabilityValidationInput {
  functionKey?: string;
  direction?: string;
}

export function validateReachabilityParams(params: ReachabilityValidationInput): ValidationResult {
  if (params.functionKey === undefined || params.functionKey === null) {
    return invalid('functionKey', 'functionKey is required');
  }
  if (typeof params.functionKey !== 'string' || params.functionKey.length === 0) {
    return invalid('functionKey', 'functionKey must be a non-empty string');
  }
  if (params.direction === undefined || params.direction === null) {
    return invalid('direction', 'direction is required');
  }
  if (params.direction !== 'forward' && params.direction !== 'backward') {
    return invalid('direction', 'direction must be "forward" or "backward"');
  }
  return VALID;
}

// ─── Root Path Params (shared by many structural/graph tools) ────────

export interface RootValidationInput {
  root?: string;
}

export function validateRootParam(params: RootValidationInput): ValidationResult {
  if (params.root === undefined || params.root === null) {
    return invalid('root', 'root is required');
  }
  if (typeof params.root !== 'string' || params.root.length === 0) {
    return invalid('root', 'root must be a non-empty string');
  }
  return VALID;
}

// ─── Feedback Params ─────────────────────────────────────────────────

export interface FeedbackValidationInput {
  violationId?: string;
  reason?: string;
}

export function validateFeedbackParams(params: FeedbackValidationInput): ValidationResult {
  if (params.violationId === undefined || params.violationId === null) {
    return invalid('violationId', 'violationId is required');
  }
  if (typeof params.violationId !== 'string' || params.violationId.length === 0) {
    return invalid('violationId', 'violationId must be a non-empty string');
  }
  return VALID;
}

// ─── Bridge Ground Params ───────────────────────────────────────────

const VALID_MEMORY_TYPES = [
  'PatternRationale',
  'ConstraintOverride',
  'DecisionContext',
  'CodeSmell',
  'Core',
  'Tribal',
  'Semantic',
  'Insight',
  'Feedback',
  'Episodic',
  'Preference',
  'Skill',
] as const;

export interface BridgeGroundValidationInput {
  memoryId?: string;
  memoryType?: string;
}

export function validateBridgeGroundParams(params: BridgeGroundValidationInput): ValidationResult {
  if (params.memoryId === undefined || params.memoryId === null) {
    return invalid('memoryId', 'memoryId is required');
  }
  if (typeof params.memoryId !== 'string' || params.memoryId.length === 0) {
    return invalid('memoryId', 'memoryId must be a non-empty string');
  }
  if (params.memoryType === undefined || params.memoryType === null) {
    return invalid('memoryType', 'memoryType is required');
  }
  if (typeof params.memoryType !== 'string' || params.memoryType.length === 0) {
    return invalid('memoryType', 'memoryType must be a non-empty string');
  }
  if (!VALID_MEMORY_TYPES.includes(params.memoryType as typeof VALID_MEMORY_TYPES[number])) {
    return invalid(
      'memoryType',
      `memoryType must be one of: ${VALID_MEMORY_TYPES.join(', ')}`,
    );
  }
  return VALID;
}

// ─── Bridge Counterfactual Params ───────────────────────────────────

export interface BridgeCounterfactualValidationInput {
  memoryId?: string;
}

export function validateBridgeCounterfactualParams(params: BridgeCounterfactualValidationInput): ValidationResult {
  if (params.memoryId === undefined || params.memoryId === null) {
    return invalid('memoryId', 'memoryId is required');
  }
  if (typeof params.memoryId !== 'string' || params.memoryId.length === 0) {
    return invalid('memoryId', 'memoryId must be a non-empty string');
  }
  return VALID;
}
