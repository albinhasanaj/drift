/**
 * drift_agent_project — Create a memory projection between namespaces.
 *
 * A projection is a filtered, optionally compressed view of one namespace's memories
 * into another namespace. Can be live (auto-syncs) or one-time.
 *
 * @example
 *   { "source_namespace": "agent://alpha/", "target_namespace": "team://backend/",
 *     "filter": { "tags": ["architecture"] }, "compression_level": 1, "live": true }
 *   → { "projection_id": "proj-..." }
 */

import type { CortexClient } from "../../bridge/client.js";
import type { McpToolDefinition, ProjectionFilter, NamespaceScope } from "../../bridge/types.js";

const NAMESPACE_URI_PATTERN = /^(agent|team|project):\/\/.+\/$/;

export function driftAgentProject(client: CortexClient): McpToolDefinition {
  return {
    name: "drift_agent_project",
    description:
      "Create a memory projection from one namespace to another. " +
      "Projections filter and optionally compress memories for cross-namespace visibility. " +
      "Set live=true for automatic sync on changes. " +
      "Example: { \"source_namespace\": \"agent://alpha/\", \"target_namespace\": \"team://backend/\", " +
      "\"compression_level\": 1, \"live\": true }",
    inputSchema: {
      type: "object",
      properties: {
        source_namespace: {
          type: "string",
          description: "Source namespace URI to project from.",
        },
        target_namespace: {
          type: "string",
          description: "Target namespace URI to project into.",
        },
        filter: {
          type: "object",
          description:
            "Filter criteria: { memory_types?: string[], min_confidence?: number, " +
            "min_importance?: string, linked_files?: string[], tags?: string[], " +
            "max_age_days?: number }. All conditions are ANDed. Defaults to no filter (all memories).",
          properties: {
            memory_types: { type: "array", items: { type: "string" } },
            min_confidence: { type: "number" },
            min_importance: { type: "string" },
            linked_files: { type: "array", items: { type: "string" } },
            tags: { type: "array", items: { type: "string" } },
            max_age_days: { type: "number" },
          },
        },
        compression_level: {
          type: "number",
          description:
            "Compression level 0–3. 0=full, 1=summary+metadata, 2=summary+examples, 3=one-line. Default: 0.",
        },
        live: {
          type: "boolean",
          description: "Whether the projection auto-syncs on changes. Default: false.",
        },
      },
      required: ["source_namespace", "target_namespace"],
    },
    handler: async (args) => {
      const sourceNamespace = args.source_namespace as string | undefined;
      const targetNamespace = args.target_namespace as string | undefined;

      if (!sourceNamespace || !NAMESPACE_URI_PATTERN.test(sourceNamespace)) {
        throw new Error(
          `Invalid source_namespace '${sourceNamespace ?? ""}'. ` +
            "Expected format: '{scope}://{name}/' (e.g. 'agent://alpha/').",
        );
      }
      if (!targetNamespace || !NAMESPACE_URI_PATTERN.test(targetNamespace)) {
        throw new Error(
          `Invalid target_namespace '${targetNamespace ?? ""}'. ` +
            "Expected format: '{scope}://{name}/' (e.g. 'team://backend/').",
        );
      }

      const compressionLevel = (args.compression_level as number | undefined) ?? 0;
      if (compressionLevel < 0 || compressionLevel > 3 || !Number.isInteger(compressionLevel)) {
        throw new Error(
          `Invalid compression_level ${compressionLevel}. Must be an integer 0–3. ` +
            "0=full, 1=summary+metadata, 2=summary+examples, 3=one-line essence.",
        );
      }

      const live = (args.live as boolean | undefined) ?? false;
      const rawFilter = (args.filter as Partial<ProjectionFilter> | undefined) ?? {};

      const filter: ProjectionFilter = {
        memory_types: rawFilter.memory_types ?? [],
        min_confidence: rawFilter.min_confidence ?? null,
        min_importance: rawFilter.min_importance ?? null,
        linked_files: rawFilter.linked_files ?? [],
        tags: rawFilter.tags ?? [],
        max_age_days: rawFilter.max_age_days ?? null,
        predicate: null,
      };

      const now = new Date().toISOString();
      const projectionId = crypto.randomUUID();

      // Parse namespace URIs into scope + name: "agent://alpha/" → { type: "agent", name: "alpha" }
      const parseNs = (uri: string): { scope: NamespaceScope; name: string } => {
        const match = uri.match(/^(agent|team|project):\/\/(.+)\/$/);
        if (!match) throw new Error(`Cannot parse namespace URI: ${uri}`);
        const scopeType = match[1];
        const scopeValue = match[2];
        let scope: NamespaceScope;
        if (scopeType === "agent") {
          scope = { type: "agent", value: { 0: scopeValue } };
        } else if (scopeType === "team") {
          scope = { type: "team", value: scopeValue };
        } else {
          scope = { type: "project", value: scopeValue };
        }
        return { scope, name: uri };
      };

      const sourceNs = parseNs(sourceNamespace);
      const targetNs = parseNs(targetNamespace);

      try {
        await client.createProjection({
          id: projectionId,
          source: sourceNs,
          target: targetNs,
          filter,
          compression_level: compressionLevel,
          live,
          created_at: now,
          created_by: sourceNs.scope.type === "agent" ? sourceNs.scope.value : { 0: "" },
        });
        return { projection_id: projectionId };
      } catch (err) {
        const message = err instanceof Error ? err.message : String(err);
        if (message.includes("PermissionDenied")) {
          throw new Error(
            `Permission denied. The creating agent needs Share permission on '${sourceNamespace}'. ` +
              "Use 'drift cortex namespaces permissions' to manage access.",
          );
        }
        throw new Error(`Failed to create projection: ${message}`);
      }
    },
  };
}
