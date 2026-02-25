/**
 * PR Comment Generator — produces readable summaries for GitHub/GitLab PRs.
 *
 * Includes violation counts, severity breakdown, and trend indicators (↑↓→).
 */

import type { AnalysisResult, PassResult } from './agent.js';

/** PR comment structure. */
export interface PrComment {
  summary: string;
  violationCount: number;
  severityBreakdown: Record<string, number>;
  trend: '↑' | '↓' | '→';
  details: string;
  markdown: string;
}

/**
 * Generate a PR comment from analysis results.
 */
export function generatePrComment(
  result: AnalysisResult,
  previousScore?: number,
): PrComment {
  const trend = determineTrend(result.score, previousScore);
  const severityBreakdown = buildSeverityBreakdown(result.passes);

  const markdown = buildMarkdown(result, trend, severityBreakdown);

  return {
    summary: result.summary,
    violationCount: result.totalViolations,
    severityBreakdown,
    trend,
    details: buildDetails(result),
    markdown,
  };
}

function determineTrend(
  currentScore: number,
  previousScore?: number,
): '↑' | '↓' | '→' {
  if (previousScore === undefined) return '→';
  if (currentScore > previousScore + 2) return '↑';
  if (currentScore < previousScore - 2) return '↓';
  return '→';
}

function buildSeverityBreakdown(passes: PassResult[]): Record<string, number> {
  const breakdown: Record<string, number> = {
    error: 0,
    warning: 0,
    info: 0,
  };

  for (const pass of passes) {
    if (pass.status === 'failed') {
      breakdown.error += pass.violations;
    } else if (pass.violations > 0) {
      breakdown.warning += pass.violations;
    }
  }

  return breakdown;
}

function buildDetails(result: AnalysisResult): string {
  return result.passes
    .map((p) => {
      const icon = p.status === 'passed' ? '✓' : p.status === 'failed' ? '✗' : '⚡';
      return `${icon} ${p.name}: ${p.violations} violations (${p.durationMs}ms)`;
    })
    .join('\n');
}

function buildMarkdown(
  result: AnalysisResult,
  trend: '↑' | '↓' | '→',
  severityBreakdown: Record<string, number>,
): string {
  const statusEmoji = result.status === 'passed' ? '✅' : '❌';
  const trendLabel =
    trend === '↑' ? 'improving' : trend === '↓' ? 'degrading' : 'stable';

  let md = `## ${statusEmoji} Drift Analysis\n\n`;
  md += `**Score:** ${result.score}/100 ${trend} (${trendLabel})\n`;
  md += `**Violations:** ${result.totalViolations}`;

  if (result.totalViolations > 0) {
    const parts: string[] = [];
    if (severityBreakdown.error > 0) parts.push(`${severityBreakdown.error} errors`);
    if (severityBreakdown.warning > 0) parts.push(`${severityBreakdown.warning} warnings`);
    if (severityBreakdown.info > 0) parts.push(`${severityBreakdown.info} info`);
    if (parts.length > 0) md += ` (${parts.join(', ')})`;
  }
  md += '\n';

  if (result.incremental) {
    md += `**Mode:** Incremental (${result.filesAnalyzed === -1 ? 'full scan' : `${result.filesAnalyzed} files`})\n`;
  }
  md += `**Duration:** ${result.durationMs}ms\n\n`;

  // Cortex memory system section
  if (result.cortexSummary) {
    const cs = result.cortexSummary;
    md += `### ${cs.badge} Cortex Memory Health\n\n`;
    md += `Status: ${cs.overallStatus}, ${cs.subsystemCount} subsystems, ${cs.degradationCount} degradations, ${cs.validationCandidates} validation candidates\n\n`;
  }

  // Bridge memory grounding section
  if (result.bridgeSummary) {
    const bs = result.bridgeSummary;
    md += `### ${bs.badge} Memory Grounding\n\n`;
    md += `${bs.validated} validated, ${bs.partial} partial, ${bs.weak} weak, ${bs.invalidated} invalidated (avg ${bs.avgScore.toFixed(2)})\n\n`;
  }

  // Pass details
  md += '<details>\n<summary>Analysis Passes</summary>\n\n';
  md += '| Pass | Status | Violations | Duration |\n';
  md += '|------|--------|------------|----------|\n';

  for (const pass of result.passes) {
    const icon = pass.status === 'passed' ? '✅' : pass.status === 'failed' ? '❌' : '⚠️';
    md += `| ${pass.name} | ${icon} ${pass.status} | ${pass.violations} | ${pass.durationMs}ms |\n`;
  }

  md += '\n</details>\n';

  return md;
}
