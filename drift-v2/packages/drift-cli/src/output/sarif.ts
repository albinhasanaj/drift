/**
 * SARIF output format — wraps violations in SARIF 2.1.0 envelope.
 */

interface SarifViolation {
  rule_id?: string;
  ruleId?: string;
  file?: string;
  line?: number;
  column?: number;
  end_line?: number;
  end_column?: number;
  severity?: string;
  message?: string;
  cwe_id?: number;
}

/**
 * Format data as SARIF 2.1.0 JSON.
 */
export function formatSarif(data: unknown): string {
  const violations = extractViolations(data);

  const sarif = {
    $schema:
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'drift',
            version: '2.0.0',
            informationUri: 'https://github.com/drift-lang/drift',
            rules: buildRules(violations),
          },
        },
        results: violations.map((v) => ({
          ruleId: v.rule_id ?? v.ruleId ?? 'unknown',
          level: severityToSarif(v.severity ?? 'warning'),
          message: { text: v.message ?? 'Violation detected' },
          locations: [
            {
              physicalLocation: {
                artifactLocation: {
                  uri: v.file ?? 'unknown',
                  uriBaseId: '%SRCROOT%',
                },
                region: {
                  startLine: Math.max(v.line ?? 1, 1),
                  ...(v.column ? { startColumn: v.column } : {}),
                  ...(v.end_line ? { endLine: v.end_line } : {}),
                  ...(v.end_column ? { endColumn: v.end_column } : {}),
                },
              },
            },
          ],
        })),
      },
    ],
  };

  return JSON.stringify(sarif, null, 2) + '\n';
}

function extractViolations(data: unknown): SarifViolation[] {
  if (Array.isArray(data)) return data as SarifViolation[];
  if (typeof data === 'object' && data !== null) {
    const obj = data as Record<string, unknown>;
    if (Array.isArray(obj.violations)) return obj.violations as SarifViolation[];
    if (Array.isArray(obj.results)) return obj.results as SarifViolation[];
  }
  return [];
}

function buildRules(violations: SarifViolation[]): Array<{ id: string; shortDescription: { text: string } }> {
  const seen = new Set<string>();
  const rules: Array<{ id: string; shortDescription: { text: string } }> = [];
  for (const v of violations) {
    const id = v.rule_id ?? v.ruleId ?? 'unknown';
    if (!seen.has(id)) {
      seen.add(id);
      rules.push({
        id,
        shortDescription: { text: v.message?.slice(0, 100) ?? id },
      });
    }
  }
  return rules;
}

function severityToSarif(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'error':
      return 'error';
    case 'warning':
      return 'warning';
    case 'info':
    case 'hint':
      return 'note';
    default:
      return 'warning';
  }
}
