-- Cloud Data Pipeline: Phase 5 — Dashboard Views
--
-- Postgres views for complex aggregation queries the GUI consumes.
-- All views inherit RLS from their underlying cloud_* tables.

-- ── v_project_health: Overall health per project ──
CREATE OR REPLACE VIEW v_project_health AS
SELECT
    p.id AS project_id,
    p.tenant_id,
    p.name AS project_name,
    -- Violation counts
    COALESCE(v.total_violations, 0) AS total_violations,
    COALESCE(v.error_violations, 0) AS error_violations,
    COALESCE(v.warning_violations, 0) AS warning_violations,
    -- Gate pass rate
    COALESCE(g.total_gates, 0) AS total_gates,
    COALESCE(g.passed_gates, 0) AS passed_gates,
    CASE WHEN COALESCE(g.total_gates, 0) > 0
        THEN ROUND((g.passed_gates::NUMERIC / g.total_gates) * 100, 1)
        ELSE 0
    END AS gate_pass_rate_pct,
    -- Pattern confidence
    COALESCE(pc.avg_confidence, 0) AS avg_pattern_confidence,
    COALESCE(pc.pattern_count, 0) AS pattern_count,
    -- DNA health
    COALESCE(dna.gene_count, 0) AS dna_gene_count,
    COALESCE(dna.avg_consistency, 0) AS dna_avg_consistency,
    -- Latest audit snapshot
    COALESCE(a.health_score, 0) AS latest_health_score
FROM projects p
LEFT JOIN LATERAL (
    SELECT
        COUNT(*) AS total_violations,
        COUNT(*) FILTER (WHERE severity = 'error') AS error_violations,
        COUNT(*) FILTER (WHERE severity = 'warning') AS warning_violations
    FROM cloud_violations cv
    WHERE cv.project_id = p.id AND cv.tenant_id = p.tenant_id
) v ON true
LEFT JOIN LATERAL (
    SELECT
        COUNT(*) AS total_gates,
        COUNT(*) FILTER (WHERE passed = true) AS passed_gates
    FROM cloud_gate_results cg
    WHERE cg.project_id = p.id AND cg.tenant_id = p.tenant_id
) g ON true
LEFT JOIN LATERAL (
    SELECT
        AVG(posterior_mean) AS avg_confidence,
        COUNT(*) AS pattern_count
    FROM cloud_pattern_confidence cpc
    WHERE cpc.project_id = p.id AND cpc.tenant_id = p.tenant_id
) pc ON true
LEFT JOIN LATERAL (
    SELECT
        COUNT(*) AS gene_count,
        AVG(consistency) AS avg_consistency
    FROM cloud_dna_genes cdg
    WHERE cdg.project_id = p.id AND cdg.tenant_id = p.tenant_id
) dna ON true
LEFT JOIN LATERAL (
    SELECT health_score
    FROM cloud_audit_snapshots cas
    WHERE cas.project_id = p.id AND cas.tenant_id = p.tenant_id
    ORDER BY cas.created_at DESC
    LIMIT 1
) a ON true;

-- ── v_trend_violations: Daily violation count over last 30 days ──
CREATE OR REPLACE VIEW v_trend_violations AS
SELECT
    tenant_id,
    project_id,
    to_timestamp(created_at)::DATE AS day,
    severity,
    COUNT(*) AS violation_count
FROM cloud_violations
WHERE created_at >= EXTRACT(EPOCH FROM (now() - INTERVAL '30 days'))::BIGINT
GROUP BY tenant_id, project_id, to_timestamp(created_at)::DATE, severity
ORDER BY day DESC;

-- ── v_top_violations: Most frequent violation rules across project ──
CREATE OR REPLACE VIEW v_top_violations AS
SELECT
    tenant_id,
    project_id,
    rule_id,
    pattern_id,
    severity,
    COUNT(*) AS occurrence_count,
    COUNT(DISTINCT file) AS affected_files,
    COUNT(*) FILTER (WHERE is_new = true) AS new_count,
    COUNT(*) FILTER (WHERE suppressed = true) AS suppressed_count
FROM cloud_violations
GROUP BY tenant_id, project_id, rule_id, pattern_id, severity
ORDER BY occurrence_count DESC;

-- ── v_security_posture: OWASP + CWE coverage per project ──
CREATE OR REPLACE VIEW v_security_posture AS
SELECT
    p.id AS project_id,
    p.tenant_id,
    p.name AS project_name,
    -- OWASP findings
    COALESCE(o.owasp_count, 0) AS owasp_finding_count,
    COALESCE(o.avg_severity, 0) AS owasp_avg_severity,
    -- Crypto findings
    COALESCE(cr.crypto_count, 0) AS crypto_finding_count,
    -- Taint flows
    COALESCE(t.taint_count, 0) AS taint_flow_count,
    COALESCE(t.unsanitized_count, 0) AS unsanitized_taint_count,
    -- Secrets
    COALESCE(s.secret_count, 0) AS secret_count,
    COALESCE(s.high_severity_secrets, 0) AS high_severity_secrets
FROM projects p
LEFT JOIN LATERAL (
    SELECT
        COUNT(*) AS owasp_count,
        AVG(severity) AS avg_severity
    FROM cloud_owasp_findings co
    WHERE co.project_id = p.id AND co.tenant_id = p.tenant_id
) o ON true
LEFT JOIN LATERAL (
    SELECT COUNT(*) AS crypto_count
    FROM cloud_crypto_findings ccf
    WHERE ccf.project_id = p.id AND ccf.tenant_id = p.tenant_id
) cr ON true
LEFT JOIN LATERAL (
    SELECT
        COUNT(*) AS taint_count,
        COUNT(*) FILTER (WHERE is_sanitized = false) AS unsanitized_count
    FROM cloud_taint_flows ctf
    WHERE ctf.project_id = p.id AND ctf.tenant_id = p.tenant_id
) t ON true
LEFT JOIN LATERAL (
    SELECT
        COUNT(*) AS secret_count,
        COUNT(*) FILTER (WHERE severity IN ('critical', 'high')) AS high_severity_secrets
    FROM cloud_secrets cs
    WHERE cs.project_id = p.id AND cs.tenant_id = p.tenant_id
) s ON true;
