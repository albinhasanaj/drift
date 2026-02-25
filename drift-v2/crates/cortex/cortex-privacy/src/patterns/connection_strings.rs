use regex::Regex;
use std::sync::LazyLock;

/// A compiled connection string detection pattern.
pub struct ConnectionStringPattern {
    pub name: &'static str,
    pub regex: &'static LazyLock<Option<Regex>>,
    pub placeholder: &'static str,
    pub base_confidence: f64,
}

macro_rules! conn_pattern {
    ($name:ident, $regex_str:expr) => {
        pub static $name: LazyLock<Option<Regex>> = LazyLock::new(|| Regex::new($regex_str).ok());
    };
}

// ── PostgreSQL ─────────────────────────────────────────────────────────────
conn_pattern!(RE_POSTGRES, r"(?i)postgres(?:ql)?://[^:]+:[^@]+@[^\s]+");

// ── MySQL ──────────────────────────────────────────────────────────────────
conn_pattern!(RE_MYSQL, r"(?i)mysql://[^:]+:[^@]+@[^\s]+");

// ── MongoDB ────────────────────────────────────────────────────────────────
conn_pattern!(RE_MONGODB, r"(?i)mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+");

// ── Redis ──────────────────────────────────────────────────────────────────
conn_pattern!(RE_REDIS, r"(?i)redis://(?:[^:]+:[^@]+@)?[^\s]+");

// ── MSSQL / SQL Server ────────────────────────────────────────────────────
conn_pattern!(
    RE_MSSQL,
    r"(?i)(?:Server|Data Source)=[^;]+;.*(?:Password|Pwd)=[^;]+"
);

// ── JDBC ───────────────────────────────────────────────────────────────────
conn_pattern!(RE_JDBC, r"(?i)jdbc:[a-z]+://[^:]+:[^@]+@[^\s]+");

// ── ODBC ───────────────────────────────────────────────────────────────────
conn_pattern!(
    RE_ODBC,
    r"(?i)(?:DSN|Driver)=[^;]+;.*(?:PWD|Password)=[^;]+"
);

// ── Base64-encoded secrets (long base64 in assignment context) ─────────────
conn_pattern!(
    RE_BASE64_SECRET,
    r#"(?i)(?:secret|key|password|token|credential)\s*[=:]\s*['"]?[A-Za-z0-9+/]{40,}={0,2}['"]?"#
);

/// All connection string patterns.
pub fn all_patterns() -> Vec<ConnectionStringPattern> {
    vec![
        ConnectionStringPattern {
            name: "postgresql",
            regex: &RE_POSTGRES,
            placeholder: "[POSTGRES_CONN]",
            base_confidence: 0.90,
        },
        ConnectionStringPattern {
            name: "mysql",
            regex: &RE_MYSQL,
            placeholder: "[MYSQL_CONN]",
            base_confidence: 0.90,
        },
        ConnectionStringPattern {
            name: "mongodb",
            regex: &RE_MONGODB,
            placeholder: "[MONGODB_CONN]",
            base_confidence: 0.90,
        },
        ConnectionStringPattern {
            name: "redis",
            regex: &RE_REDIS,
            placeholder: "[REDIS_CONN]",
            base_confidence: 0.85,
        },
        ConnectionStringPattern {
            name: "mssql",
            regex: &RE_MSSQL,
            placeholder: "[MSSQL_CONN]",
            base_confidence: 0.85,
        },
        ConnectionStringPattern {
            name: "jdbc",
            regex: &RE_JDBC,
            placeholder: "[JDBC_CONN]",
            base_confidence: 0.85,
        },
        ConnectionStringPattern {
            name: "odbc",
            regex: &RE_ODBC,
            placeholder: "[ODBC_CONN]",
            base_confidence: 0.80,
        },
        ConnectionStringPattern {
            name: "base64_secret",
            regex: &RE_BASE64_SECRET,
            placeholder: "[ENCODED_SECRET]",
            base_confidence: 0.70,
        },
    ]
}
