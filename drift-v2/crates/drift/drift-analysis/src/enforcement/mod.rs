//! Enforcement layer — transforms analysis into actionable pass/fail decisions.
//!
//! Subsystems:
//! - `rules` — Pattern matcher → violations → severity assignment
//! - `gates` — 6 quality gates with DAG-based orchestration
//! - `reporters` — SARIF 2.1.0, JSON, console output
//! - `policy` — 4 aggregation modes for gate results
//! - `audit` — 5-factor health scoring, degradation detection
//! - `feedback` — Tricorder-style FP tracking, auto-disable

pub mod rules;
pub mod gates;
pub mod reporters;
pub mod policy;
pub mod audit;
pub mod feedback;
