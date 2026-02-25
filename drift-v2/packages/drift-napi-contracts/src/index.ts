// @drift/napi-contracts — Single source of truth for Rust↔TypeScript NAPI signatures

// Interface
export type { DriftNapi } from './interface.js';
export { DRIFT_NAPI_METHOD_COUNT, DRIFT_NAPI_METHOD_NAMES } from './interface.js';

// Types (all re-exported from types barrel)
export type * from './types/index.js';

// Loader
export { loadNapi, setNapi, resetNapi, isNapiOverridden, isNapiStub, NapiLoadError } from './loader.js';

// Stub
export { createStubNapi } from './stub.js';

// Project root resolution
export { resolveProjectRoot } from './project_root.js';

// Validation
export {
  validateScanParams,
  validateContextParams,
  validateSimulateParams,
  validateReachabilityParams,
  validateRootParam,
  validateFeedbackParams,
  validateBridgeGroundParams,
  validateBridgeCounterfactualParams,
} from './validation.js';
export type {
  ValidationResult,
  ScanValidationInput,
  ContextValidationInput,
  SimulateValidationInput,
  ReachabilityValidationInput,
  RootValidationInput,
  FeedbackValidationInput,
  BridgeGroundValidationInput,
  BridgeCounterfactualValidationInput,
} from './validation.js';
