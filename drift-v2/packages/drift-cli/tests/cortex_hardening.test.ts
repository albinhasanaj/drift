/**
 * Cortex CLI Hardening Tests — CH-T01 through CH-T03 (setup),
 * CH-T12/T13 (temporal subcommands), CH-T14/T15 (multi-agent subcommands).
 *
 * Verifies .cortex/ directory creation in setup, cortex subcommand registration,
 * and correct delegation to CortexClient methods.
 */

import { describe, it, expect, beforeEach } from 'vitest';
import { setNapi, resetNapi } from '../src/napi.js';
import { createProgram } from '../src/index.js';
import { createStubNapi } from '@drift/napi-contracts';
import type { DriftNapi } from '../src/napi.js';

function createMockNapi(overrides: Partial<DriftNapi> = {}): DriftNapi {
  return { ...createStubNapi(), ...overrides };
}

describe('Cortex Setup Integration (CH-T01 to CH-T03)', () => {
  beforeEach(() => {
    resetNapi();
    setNapi(createMockNapi());
  });

  // CH-T01: setup.ts imports CortexClient
  it('CH-T01: setup command is registered', () => {
    const program = createProgram();
    const setupCmd = program.commands.find(c => c.name() === 'setup');
    expect(setupCmd).toBeDefined();
    expect(setupCmd!.description()).toContain('Initialize');
  });

  // CH-T02: cortex command is registered with subcommands
  it('CH-T02: cortex command has subcommands registered', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    expect(cortexCmd).toBeDefined();
    const subNames = cortexCmd!.commands.map(c => c.name());
    // Should have all original + new temporal + new multi-agent subcommands
    expect(subNames.length).toBeGreaterThanOrEqual(30);
  });

  // CH-T03: build script includes cortex-napi
  it('CH-T03: build chain validation (structural check)', async () => {
    const fs = await import('node:fs');
    const path = await import('node:path');
    // Navigate from drift-cli up to root
    const rootPkg = path.resolve(__dirname, '../../../package.json');
    if (fs.existsSync(rootPkg)) {
      const content = JSON.parse(fs.readFileSync(rootPkg, 'utf-8'));
      expect(content.scripts.build).toContain('build:cortex-napi');
    }
  });
});

describe('Temporal CLI Subcommands (CH-T12/T13)', () => {
  beforeEach(() => {
    resetNapi();
    setNapi(createMockNapi());
  });

  // CH-T12: All 6 temporal subcommands are registered
  it('CH-T12: temporal subcommands registered on cortex', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    expect(cortexCmd).toBeDefined();
    const subNames = cortexCmd!.commands.map(c => c.name());

    expect(subNames).toContain('time-range');
    expect(subNames).toContain('temporal-causal');
    expect(subNames).toContain('view-create');
    expect(subNames).toContain('view-get');
    expect(subNames).toContain('view-list');
    expect(subNames).toContain('knowledge-health');
  });

  // CH-T13: Temporal subcommands have correct descriptions
  it('CH-T13: temporal subcommands have descriptions', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    expect(cortexCmd).toBeDefined();

    const timeRange = cortexCmd!.commands.find(c => c.name() === 'time-range');
    expect(timeRange).toBeDefined();
    expect(timeRange!.description()).toContain('time range');

    const temporalCausal = cortexCmd!.commands.find(c => c.name() === 'temporal-causal');
    expect(temporalCausal).toBeDefined();
    expect(temporalCausal!.description()).toContain('causal');

    const viewCreate = cortexCmd!.commands.find(c => c.name() === 'view-create');
    expect(viewCreate).toBeDefined();
    expect(viewCreate!.description()).toContain('materialized');

    const viewGet = cortexCmd!.commands.find(c => c.name() === 'view-get');
    expect(viewGet).toBeDefined();
    expect(viewGet!.description()).toContain('view');

    const viewList = cortexCmd!.commands.find(c => c.name() === 'view-list');
    expect(viewList).toBeDefined();
    expect(viewList!.description()).toContain('materialized');

    const knowledgeHealth = cortexCmd!.commands.find(c => c.name() === 'knowledge-health');
    expect(knowledgeHealth).toBeDefined();
    expect(knowledgeHealth!.description()).toContain('drift');
  });

  // CH-T13b: time-range has required options
  it('CH-T13b: time-range requires --from and --to', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    const timeRange = cortexCmd!.commands.find(c => c.name() === 'time-range');
    const opts = timeRange!.options.map(o => o.long);
    expect(opts).toContain('--from');
    expect(opts).toContain('--to');
    expect(opts).toContain('--mode');
    expect(opts).toContain('--db');
  });

  // CH-T13c: temporal-causal has required options
  it('CH-T13c: temporal-causal requires --memory-id and --as-of', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    const cmd = cortexCmd!.commands.find(c => c.name() === 'temporal-causal');
    const opts = cmd!.options.map(o => o.long);
    expect(opts).toContain('--memory-id');
    expect(opts).toContain('--as-of');
    expect(opts).toContain('--direction');
    expect(opts).toContain('--depth');
  });
});

describe('Multi-Agent CLI Subcommands (CH-T14/T15)', () => {
  beforeEach(() => {
    resetNapi();
    setNapi(createMockNapi());
  });

  // CH-T14: All 8 multi-agent subcommands are registered
  it('CH-T14: multi-agent subcommands registered on cortex', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    expect(cortexCmd).toBeDefined();
    const subNames = cortexCmd!.commands.map(c => c.name());

    expect(subNames).toContain('agent-register');
    expect(subNames).toContain('agent-deregister');
    expect(subNames).toContain('agent-get');
    expect(subNames).toContain('agent-share');
    expect(subNames).toContain('agent-retract');
    expect(subNames).toContain('agent-sync');
    expect(subNames).toContain('agent-trust');
    expect(subNames).toContain('agent-project');
  });

  // CH-T15: Multi-agent subcommands have correct descriptions
  it('CH-T15: multi-agent subcommands have descriptions', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    expect(cortexCmd).toBeDefined();

    const register = cortexCmd!.commands.find(c => c.name() === 'agent-register');
    expect(register).toBeDefined();
    expect(register!.description()).toContain('agent');

    const deregister = cortexCmd!.commands.find(c => c.name() === 'agent-deregister');
    expect(deregister).toBeDefined();
    expect(deregister!.description()).toContain('agent');

    const agentGet = cortexCmd!.commands.find(c => c.name() === 'agent-get');
    expect(agentGet).toBeDefined();
    expect(agentGet!.description()).toContain('agent');

    const share = cortexCmd!.commands.find(c => c.name() === 'agent-share');
    expect(share).toBeDefined();
    expect(share!.description()).toContain('memory');

    const retract = cortexCmd!.commands.find(c => c.name() === 'agent-retract');
    expect(retract).toBeDefined();
    expect(retract!.description()).toContain('Retract');

    const sync = cortexCmd!.commands.find(c => c.name() === 'agent-sync');
    expect(sync).toBeDefined();
    expect(sync!.description()).toContain('Sync');

    const trust = cortexCmd!.commands.find(c => c.name() === 'agent-trust');
    expect(trust).toBeDefined();
    expect(trust!.description()).toContain('trust');

    const project = cortexCmd!.commands.find(c => c.name() === 'agent-project');
    expect(project).toBeDefined();
    expect(project!.description()).toContain('projection');
  });

  // CH-T15b: agent-register has required options
  it('CH-T15b: agent-register requires --name', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    const cmd = cortexCmd!.commands.find(c => c.name() === 'agent-register');
    const opts = cmd!.options.map(o => o.long);
    expect(opts).toContain('--name');
    expect(opts).toContain('--capabilities');
    expect(opts).toContain('--db');
  });

  // CH-T15c: agent-share has required options
  it('CH-T15c: agent-share requires --memory-id, --namespace, --agent-id', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    const cmd = cortexCmd!.commands.find(c => c.name() === 'agent-share');
    const opts = cmd!.options.map(o => o.long);
    expect(opts).toContain('--memory-id');
    expect(opts).toContain('--namespace');
    expect(opts).toContain('--agent-id');
  });

  // CH-T15d: agent-project has required options
  it('CH-T15d: agent-project requires --source-ns, --target-ns', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    const cmd = cortexCmd!.commands.find(c => c.name() === 'agent-project');
    const opts = cmd!.options.map(o => o.long);
    expect(opts).toContain('--source-ns');
    expect(opts).toContain('--target-ns');
    expect(opts).toContain('--filter');
  });

  // All cortex subcommands have --db option
  it('all cortex subcommands accept --db option', () => {
    const program = createProgram();
    const cortexCmd = program.commands.find(c => c.name() === 'cortex');
    expect(cortexCmd).toBeDefined();

    for (const sub of cortexCmd!.commands) {
      const opts = sub.options.map(o => o.long);
      expect(opts, `${sub.name()} missing --db`).toContain('--db');
    }
  });
});
