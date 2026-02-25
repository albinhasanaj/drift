/**
 * NAPI bridge — re-exports from @drift/napi-contracts.
 *
 * PH-INFRA-13: This file previously contained a divergent local DriftNapi
 * interface with 22 methods. It is now a thin re-export from the canonical
 * contracts package, ensuring all packages share the same NAPI signatures.
 */

export { loadNapi, setNapi, resetNapi } from '@drift/napi-contracts';
export type { DriftNapi } from '@drift/napi-contracts';
