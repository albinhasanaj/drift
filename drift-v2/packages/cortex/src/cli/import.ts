/**
 * drift cortex import <file> — Import memories from JSON.
 */

import { readFileSync } from "node:fs";

import type { CortexClient } from "../bridge/client.js";
import type { BaseMemory } from "../bridge/types.js";

export async function importCommand(client: CortexClient, filePath: string): Promise<void> {
  const raw = readFileSync(filePath, "utf-8");
  const data: unknown = JSON.parse(raw) as unknown;

  const memories: BaseMemory[] = Array.isArray(data)
    ? (data as BaseMemory[])
    : (((data as Record<string, unknown>).memories as BaseMemory[] | undefined) ?? []);

  console.log(`\n  Importing ${memories.length} memories from ${filePath}...`);

  let imported = 0;
  let skipped = 0;
  let errors = 0;

  for (const memory of memories) {
    try {
      await client.memoryCreate(memory);
      imported++;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes("UNIQUE") || msg.includes("duplicate")) {
        skipped++;
      } else {
        errors++;
        console.error(`  ✗ ${memory.id}: ${msg}`);
      }
    }
  }

  console.log(`  ─────────────────────────────────────`);
  console.log(`  Imported: ${imported}`);
  console.log(`  Skipped:  ${skipped} (duplicates)`);
  console.log(`  Errors:   ${errors}`);
  console.log();
}
