/**
 * drift cortex add <type> — Interactive memory creation.
 */

import type { CortexClient } from "../bridge/client.js";
import type { MemoryType, TypedContent } from "../bridge/types.js";

/**
 * Build minimal typed content for a given memory type.
 * In a full interactive CLI this would prompt the user; here we accept JSON.
 */
function buildContent(memoryType: MemoryType, contentJson: string): TypedContent {
  const data: unknown = JSON.parse(contentJson) as unknown;
  return { type: memoryType, data } as TypedContent;
}

export async function addCommand(
  client: CortexClient,
  memoryType: string,
  summary: string,
  contentJson: string,
  tags?: string[],
): Promise<void> {
  const mt = memoryType as MemoryType;
  const content = buildContent(mt, contentJson);
  const now = new Date().toISOString();
  const id = crypto.randomUUID();

  await client.memoryCreate({
    id,
    memory_type: mt,
    content,
    summary,
    transaction_time: now,
    valid_time: now,
    valid_until: null,
    confidence: 1.0,
    importance: "normal",
    last_accessed: now,
    access_count: 0,
    linked_patterns: [],
    linked_constraints: [],
    linked_files: [],
    linked_functions: [],
    tags: tags ?? [],
    archived: false,
    superseded_by: null,
    supersedes: null,
    content_hash: "",
  });

  console.log(`\n  Created ${mt} memory: ${id}`);
  console.log(`  Summary: ${summary}\n`);
}
