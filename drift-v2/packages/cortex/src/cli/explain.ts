/**
 * drift cortex explain <memory-id> — Full memory with causal chain.
 */

import type { CortexClient } from "../bridge/client.js";

export async function explainCommand(client: CortexClient, memoryId: string): Promise<void> {
  const [memory, narrative, traversal] = await Promise.all([
    client.memoryGet(memoryId),
    client.causalGetWhy(memoryId),
    client.causalTraverse(memoryId),
  ]);

  console.log(`\n  Memory: ${memory.id}`);
  console.log(`  ─────────────────────────────────────`);
  console.log(`  Type:       ${memory.memory_type}`);
  console.log(`  Importance: ${memory.importance}`);
  console.log(`  Confidence: ${(memory.confidence * 100).toFixed(1)}%`);
  console.log(`  Summary:    ${memory.summary}`);
  console.log(`  Tags:       ${memory.tags.join(", ") || "(none)"}`);
  console.log(`  Created:    ${memory.transaction_time}`);
  console.log(`  Accessed:   ${memory.access_count} times`);

  if (memory.linked_files.length > 0) {
    console.log(`\n  Linked Files:`);
    for (const f of memory.linked_files) {
      const lines = f.line_start ? `:${f.line_start}${f.line_end ? `-${f.line_end}` : ""}` : "";
      console.log(`    ${f.file_path}${lines}`);
    }
  }

  console.log(`\n  Causal Narrative:`);
  console.log(`  ${narrative.summary}`);

  if (traversal.nodes.length > 0) {
    console.log(`\n  Causal Graph (${traversal.nodes.length} connected):`);
    for (const node of traversal.nodes) {
      const strength = (node.path_strength * 100).toFixed(0);
      console.log(`    depth ${node.depth}: ${node.memory_id} (${strength}% strength)`);
    }
  }

  console.log();
}
