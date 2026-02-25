/**
 * Command registration — registers all 29 CLI commands.
 */

import type { Command } from 'commander';
import { registerScanCommand } from './scan.js';
import { registerCheckCommand } from './check.js';
import { registerStatusCommand } from './status.js';
import { registerPatternsCommand } from './patterns.js';
import { registerViolationsCommand } from './violations.js';
import { registerImpactCommand } from './impact.js';
import { registerSimulateCommand } from './simulate.js';
import { registerAuditCommand } from './audit.js';
import { registerSetupCommand } from './setup.js';
import { registerDoctorCommand } from './doctor.js';
import { registerExportCommand } from './export.js';
import { registerExplainCommand } from './explain.js';
import { registerFixCommand } from './fix.js';
import { registerAnalyzeCommand } from './analyze.js';
import { registerReportCommand } from './report.js';
import { registerGcCommand } from './gc.js';
import { registerSecurityCommand } from './security.js';
import { registerContractsCommand } from './contracts.js';
import { registerCouplingCommand } from './coupling.js';
import { registerDnaCommand } from './dna.js';
import { registerContextCommand } from './context.js';
import { registerDismissCommand } from './dismiss.js';
import { registerSuppressCommand } from './suppress.js';
import { registerTaintCommand } from './taint.js';
import { registerErrorsCommand } from './errors.js';
import { registerTestQualityCommand } from './test-quality.js';
import { registerCortexCommand } from './cortex.js';
import { registerBridgeCommand } from './bridge.js';
import { registerValidatePackCommand } from './validate-pack.js';
import { registerCloudCommand } from './cloud.js';
import { registerApproveCommand } from './approve.js';

/**
 * Register all CLI commands on the program.
 */
export function registerAllCommands(program: Command): void {
  // Core pipeline
  registerScanCommand(program);
  registerAnalyzeCommand(program);
  registerCheckCommand(program);
  registerStatusCommand(program);
  registerReportCommand(program);
  // Exploration
  registerPatternsCommand(program);
  registerViolationsCommand(program);
  registerSecurityCommand(program);
  registerContractsCommand(program);
  registerCouplingCommand(program);
  registerDnaCommand(program);
  registerTaintCommand(program);
  registerErrorsCommand(program);
  registerTestQualityCommand(program);
  registerImpactCommand(program);
  // Feedback
  registerFixCommand(program);
  registerDismissCommand(program);
  registerSuppressCommand(program);
  registerExplainCommand(program);
  registerApproveCommand(program);
  // Advanced
  registerSimulateCommand(program);
  registerContextCommand(program);
  registerAuditCommand(program);
  registerExportCommand(program);
  // Operational
  registerGcCommand(program);
  registerSetupCommand(program);
  registerDoctorCommand(program);
  // Cortex memory system
  registerCortexCommand(program);
  // Bridge: memory grounding, causal intelligence, learning
  registerBridgeCommand(program);
  // Framework pack validation
  registerValidatePackCommand(program);
  // Cloud sync
  registerCloudCommand(program);
}

export { registerAnalyzeCommand } from './analyze.js';
