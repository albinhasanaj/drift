/**
 * drift_memory_add — Create a memory with auto-dedup and causal inference.
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition, MemoryType, TypedContent } from "../../bridge/types.js";

export function driftMemoryAdd(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_memory_add",
    description:
      "Create a new memory in the Cortex system. Automatically deduplicates " +
      "against existing memories and infers causal relationships.",
    inputSchema: {
      type: "object",
      properties: {
        memory_type: {
          type: "string",
          description: "One of the 23 memory types (e.g. 'episodic', 'tribal', 'decision').",
          enum: [
            "core",
            "tribal",
            "procedural",
            "semantic",
            "episodic",
            "decision",
            "insight",
            "reference",
            "preference",
            "pattern_rationale",
            "constraint_override",
            "decision_context",
            "code_smell",
            "agent_spawn",
            "entity",
            "goal",
            "feedback",
            "workflow",
            "conversation",
            "incident",
            "meeting",
            "skill",
            "environment",
          ],
        },
        content: {
          type: "object",
          description:
            "Typed content matching the memory_type schema. Must include 'type' and 'data' fields.",
        },
        summary: { type: "string", description: "~20 token summary for compression." },
        importance: {
          type: "string",
          enum: ["low", "normal", "high", "critical"],
          description: "Importance level. Defaults to 'normal'.",
        },
        tags: {
          type: "array",
          items: { type: "string" },
          description: "Free-form tags for categorization.",
        },
      },
      required: ["memory_type", "content", "summary"],
    },
    handler: async (args) => {
      const now = new Date().toISOString();
      const id = crypto.randomUUID();
      const memory = {
        id,
        memory_type: args.memory_type as MemoryType,
        content: args.content as TypedContent,
        summary: args.summary as string,
        transaction_time: now,
        valid_time: now,
        valid_until: null,
        confidence: 1.0,
        importance: (args.importance as string) ?? "normal",
        last_accessed: now,
        access_count: 0,
        linked_patterns: [],
        linked_constraints: [],
        linked_files: [],
        linked_functions: [],
        tags: (args.tags as string[]) ?? [],
        archived: false,
        superseded_by: null,
        supersedes: null,
        content_hash: "",
      };
      await client.memoryCreate(memory as never);
      return { id, status: "created" };
    },
  };
}
