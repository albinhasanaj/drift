/**
 * Decision Mining — TypeScript orchestration layer.
 *
 * Provides ADR synthesis and category definitions for the
 * Rust-powered decision mining engine.
 */

export { AdrSynthesizer, type MinedDecision, type SynthesizedAdr } from "./adr_synthesis.js";
export { ALL_CATEGORIES, CATEGORY_INFO, type DecisionCategory } from "./categories.js";
