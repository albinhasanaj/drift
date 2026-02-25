/**
 * ToolFilter — language-aware catalog filtering with core tool protection.
 *
 * - Filters catalog by project languages (from drift_status().languages)
 * - NEVER filters core tools: drift_status, drift_context, drift_scan, drift_check, drift_violations
 * - Falls back to full catalog if language detection fails
 *
 * PH-INFRA-08
 */

export interface InternalToolEntry {
  name: string;
  description: string;
  category: string;
  estimatedTokens: string;
}

/** Tools that are never filtered, regardless of project language. */
const CORE_TOOLS = new Set([
  'drift_status',
  'drift_context',
  'drift_scan',
  'drift_check',
  'drift_violations',
  'drift_tool',
  'drift_discover',
  'drift_workflow',
]);

/** Language → tool keyword associations for filtering. */
const LANGUAGE_TOOL_KEYWORDS: Record<string, string[]> = {
  TypeScript: ['typescript', 'ts', 'node', 'npm', 'react', 'angular', 'vue'],
  JavaScript: ['javascript', 'js', 'node', 'npm', 'react', 'angular', 'vue'],
  Python: ['python', 'py', 'pip', 'django', 'flask', 'fastapi'],
  Rust: ['rust', 'cargo', 'crate'],
  Go: ['go', 'golang'],
  Java: ['java', 'jvm', 'spring', 'maven', 'gradle'],
  CSharp: ['csharp', 'cs', 'dotnet', '.net'],
};

export class ToolFilter {
  /** Filter a tool catalog by detected project languages.
   *
   * @param catalog - All tools in the catalog
   * @param languages - Detected languages from drift_status (language → file count)
   * @returns Filtered catalog — core tools always included
   */
  filter(
    catalog: Map<string, InternalToolEntry>,
    languages: Record<string, number> | null,
  ): Map<string, InternalToolEntry> {
    // Fallback: if no languages detected, return full catalog
    if (!languages || Object.keys(languages).length === 0) {
      return catalog;
    }

    const detectedLanguages = Object.keys(languages);
    const relevantKeywords = new Set<string>();

    for (const lang of detectedLanguages) {
      const keywords = LANGUAGE_TOOL_KEYWORDS[lang];
      if (keywords) {
        for (const kw of keywords) {
          relevantKeywords.add(kw);
        }
      }
    }

    // If no language keywords match, return full catalog (safe fallback)
    if (relevantKeywords.size === 0) {
      return catalog;
    }

    const filtered = new Map<string, InternalToolEntry>();

    for (const [name, tool] of catalog) {
      // Core tools always pass
      if (CORE_TOOLS.has(name)) {
        filtered.set(name, tool);
        continue;
      }

      // Language-agnostic tools (analysis, enforcement, feedback) always pass
      const agnosticCategories = new Set([
        'analysis',
        'enforcement',
        'feedback',
        'exploration',
        'operational',
        'graph',
        'structural',
      ]);
      if (agnosticCategories.has(tool.category)) {
        filtered.set(name, tool);
        continue;
      }

      // For language-specific tools, check if description matches
      const descLower = tool.description.toLowerCase();
      const nameMatch = relevantKeywords.has(name.toLowerCase());
      const descMatch = [...relevantKeywords].some((kw) => descLower.includes(kw));

      if (nameMatch || descMatch) {
        filtered.set(name, tool);
      }
    }

    return filtered;
  }
}
