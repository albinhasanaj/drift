#!/usr/bin/env node
/**
 * RLS Verification Script — tests tenant isolation on cloud tables.
 *
 * Usage: SUPABASE_URL=... SUPABASE_SERVICE_ROLE_KEY=... node supabase/tests/verify-rls.mjs
 */

const SUPABASE_URL = process.env.SUPABASE_URL;
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
const ANON_KEY = process.env.SUPABASE_ANON_KEY;

if (!SUPABASE_URL || !SERVICE_KEY) {
  console.error('Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY env vars');
  process.exit(1);
}

const REST = `${SUPABASE_URL}/rest/v1`;
const TENANT_A = 'a0000000-0000-0000-0000-000000000001';
const TENANT_B = 'b0000000-0000-0000-0000-000000000002';
const PROJECT_A = 'c0000000-0000-0000-0000-000000000001';
const PROJECT_B = 'c0000000-0000-0000-0000-000000000002';

let passed = 0, failed = 0;

function ok(cond, msg) {
  if (cond) { console.log(`  ✅ ${msg}`); passed++; }
  else { console.error(`  ❌ ${msg}`); failed++; }
}

async function api(path, key, opts = {}) {
  const res = await fetch(`${REST}${path}`, {
    ...opts,
    headers: {
      'Content-Type': 'application/json',
      'apikey': key,
      'Authorization': `Bearer ${key}`,
      'Prefer': opts.prefer || '',
      ...opts.headers,
    },
  });
  const text = await res.text();
  if (!res.ok && opts.method !== 'DELETE')
    throw new Error(`${res.status} on ${path}: ${text.slice(0, 300)}`);
  return text ? JSON.parse(text) : null;
}

async function main() {
  console.log('=== Drift Cloud RLS Verification ===\n');

  // ── Step 1: Seed parent rows (tenants + projects) ──
  console.log('1. Seeding parent rows (tenants, projects)...');

  // Clean child tables first (FK constraint order)
  await api(`/cloud_violations?tenant_id=in.(${TENANT_A},${TENANT_B})`, SERVICE_KEY, { method: 'DELETE' }).catch(() => {});
  await api(`/cloud_gate_results?tenant_id=in.(${TENANT_A},${TENANT_B})`, SERVICE_KEY, { method: 'DELETE' }).catch(() => {});
  // Clean projects, then tenants
  await api(`/projects?id=in.(${PROJECT_A},${PROJECT_B})`, SERVICE_KEY, { method: 'DELETE' }).catch(() => {});
  await api(`/tenants?id=in.(${TENANT_A},${TENANT_B})`, SERVICE_KEY, { method: 'DELETE' }).catch(() => {});

  // Create tenants
  await api('/tenants', SERVICE_KEY, {
    method: 'POST', prefer: 'return=minimal,resolution=merge-duplicates',
    headers: { 'Prefer': 'return=minimal,resolution=merge-duplicates' },
    body: JSON.stringify([
      { id: TENANT_A, name: 'Test Tenant A', email: 'a@test.dev' },
      { id: TENANT_B, name: 'Test Tenant B', email: 'b@test.dev' },
    ]),
  });

  // Create projects
  await api('/projects', SERVICE_KEY, {
    method: 'POST', prefer: 'return=minimal,resolution=merge-duplicates',
    headers: { 'Prefer': 'return=minimal,resolution=merge-duplicates' },
    body: JSON.stringify([
      { id: PROJECT_A, tenant_id: TENANT_A, name: 'Project Alpha' },
      { id: PROJECT_B, tenant_id: TENANT_B, name: 'Project Beta' },
    ]),
  });
  console.log('  Created 2 tenants + 2 projects\n');

  // ── Step 2: Seed cloud data rows ──
  console.log('2. Seeding cloud data (violations, gates)...');

  // Tenant A: 2 violations (matching actual schema columns)
  await api('/cloud_violations', SERVICE_KEY, {
    method: 'POST', prefer: 'return=minimal',
    body: JSON.stringify([
      { tenant_id: TENANT_A, project_id: PROJECT_A, local_id: 'v-001', file: 'src/app.ts', line: 10, severity: 'warning', pattern_id: 'pat-1', rule_id: 'no-unused-vars', message: 'Unused var x', created_at: Date.now() },
      { tenant_id: TENANT_A, project_id: PROJECT_A, local_id: 'v-002', file: 'src/utils.ts', line: 25, severity: 'error', pattern_id: 'pat-2', rule_id: 'no-any', message: 'No any type', created_at: Date.now() },
    ]),
  });

  // Tenant B: 1 violation
  await api('/cloud_violations', SERVICE_KEY, {
    method: 'POST', prefer: 'return=minimal',
    body: JSON.stringify([
      { tenant_id: TENANT_B, project_id: PROJECT_B, local_id: 'v-003', file: 'src/handler.ts', line: 50, severity: 'error', pattern_id: 'pat-3', rule_id: 'max-complexity', message: 'Complexity 15', created_at: Date.now() },
    ]),
  });

  // Gate results (matching actual schema: local_id BIGINT, status, summary, run_at required)
  await api('/cloud_gate_results', SERVICE_KEY, {
    method: 'POST', prefer: 'return=minimal',
    body: JSON.stringify([
      { tenant_id: TENANT_A, project_id: PROJECT_A, local_id: 1, gate_id: 'quality-gate', status: 'passed', passed: true, score: 85.0, summary: 'All gates passed', run_at: Date.now() },
      { tenant_id: TENANT_B, project_id: PROJECT_B, local_id: 2, gate_id: 'quality-gate', status: 'failed', passed: false, score: 45.0, summary: 'Gate failed', run_at: Date.now() },
    ]),
  });
  console.log('  Seeded: tenant_a(2 violations, 1 gate), tenant_b(1 violation, 1 gate)\n');

  // ── Step 3: Service role sees ALL rows ──
  console.log('3. Service role sees all data (bypasses RLS)...');
  const allV = await api(`/cloud_violations?select=tenant_id,local_id&tenant_id=in.(${TENANT_A},${TENANT_B})&order=local_id`, SERVICE_KEY);
  ok(allV.length === 3, `Service role sees 3 violations (got ${allV.length})`);
  const allG = await api(`/cloud_gate_results?select=tenant_id,local_id&tenant_id=in.(${TENANT_A},${TENANT_B})&order=local_id`, SERVICE_KEY);
  ok(allG.length === 2, `Service role sees 2 gate results (got ${allG.length})`);

  // ── Step 4: Anon key with NO tenant context sees 0 rows ──
  if (ANON_KEY) {
    console.log('\n4. Anon key (no tenant context) → RLS blocks all rows...');
    const anonV = await api('/cloud_violations?select=local_id', ANON_KEY);
    ok(anonV.length === 0, `Anon key sees 0 violations (got ${anonV.length})`);
    const anonG = await api('/cloud_gate_results?select=local_id', ANON_KEY);
    ok(anonG.length === 0, `Anon key sees 0 gate results (got ${anonG.length})`);
  } else {
    console.log('\n4. Skipped anon key test (SUPABASE_ANON_KEY not set)');
  }

  // ── Step 5: Dashboard views exist and are queryable ──
  console.log('\n5. Dashboard views...');
  for (const view of ['v_project_health', 'v_trend_violations', 'v_top_violations', 'v_security_posture']) {
    try {
      const rows = await api(`/${view}?limit=1`, SERVICE_KEY);
      ok(Array.isArray(rows), `${view} queryable (${rows.length} rows)`);
    } catch (e) {
      ok(false, `${view}: ${e.message.slice(0, 100)}`);
    }
  }

  // ── Step 6: Spot-check tables across all 3 tiers ──
  console.log('\n6. Spot-check tables (T1, T2, T3)...');
  const tables = [
    'cloud_violations', 'cloud_gate_results', 'cloud_detections', 'cloud_functions',
    'cloud_bridge_memories', 'cloud_grounding_results',
    'cloud_memories', 'cloud_causal_edges',
    'cloud_agent_registry', 'cloud_migration_projects',
  ];
  for (const t of tables) {
    try {
      const rows = await api(`/${t}?limit=0`, SERVICE_KEY);
      ok(Array.isArray(rows), `${t} ✓`);
    } catch (e) {
      ok(false, `${t}: ${e.message.slice(0, 100)}`);
    }
  }

  // ── Step 7: Cleanup ──
  console.log('\n7. Cleaning up test data...');
  await api(`/cloud_violations?tenant_id=in.(${TENANT_A},${TENANT_B})`, SERVICE_KEY, { method: 'DELETE' }).catch(() => {});
  await api(`/cloud_gate_results?tenant_id=in.(${TENANT_A},${TENANT_B})`, SERVICE_KEY, { method: 'DELETE' }).catch(() => {});
  await api(`/projects?id=in.(${PROJECT_A},${PROJECT_B})`, SERVICE_KEY, { method: 'DELETE' }).catch(() => {});
  await api(`/tenants?id=in.(${TENANT_A},${TENANT_B})`, SERVICE_KEY, { method: 'DELETE' }).catch(() => {});
  console.log('  Done.\n');

  console.log(`=== Results: ${passed} passed, ${failed} failed ===`);
  process.exit(failed > 0 ? 1 : 0);
}

main().catch(e => { console.error('Fatal:', e); process.exit(1); });
