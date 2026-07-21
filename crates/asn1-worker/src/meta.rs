//! Shared helpers for the per-object discovery/description metadata the
//! `vgi-lint` strict profile expects on every function and table.
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted here: it belongs on
//! the catalog object only (VGI139); the catalog's `source_url` already points at
//! the repo.

/// Encode comma-separated keywords as the JSON array of strings `vgi.keywords`
/// requires (VGI138).
pub fn keywords_json(keywords: &str) -> String {
    let items: Vec<serde_json::Value> = keywords
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| serde_json::Value::String(k.to_string()))
        .collect();
    serde_json::Value::Array(items).to_string()
}

/// One catalog-level `vgi.agent_test_tasks` task run by `vgi-lint simulate`.
///
/// Only `prompt` is shown to the analyst; `reference_sql` and `success_criteria`
/// are **grader-only** (never surfaced) — one exercises the object for coverage
/// and grades the analyst's answer, the other is an LLM-judge fallback rubric.
pub struct AgentTask {
    pub name: &'static str,
    pub prompt: &'static str,
    /// Canonical deterministic solution (grader-only). Verified against the live
    /// worker so exact-compare grading is sound.
    pub reference_sql: &'static str,
    /// Optional LLM-judge rubric (grader-only) — a tier-3 fallback so a correct
    /// answer shaped differently from `reference_sql` still passes.
    pub success_criteria: Option<&'static str>,
    /// Relax strict row-order comparison for multi-row references.
    pub unordered: bool,
}

/// Build the `vgi.agent_test_tasks` JSON array (VGI407) from [`AgentTask`]s.
pub fn agent_test_tasks_json(tasks: &[AgentTask]) -> String {
    let items: Vec<serde_json::Value> = tasks
        .iter()
        .map(|t| {
            let mut obj = serde_json::Map::new();
            obj.insert("name".into(), t.name.into());
            obj.insert("prompt".into(), t.prompt.into());
            obj.insert("reference_sql".into(), t.reference_sql.into());
            if let Some(sc) = t.success_criteria {
                obj.insert("success_criteria".into(), sc.into());
            }
            if t.unordered {
                obj.insert("unordered".into(), true.into());
            }
            serde_json::Value::Object(obj)
        })
        .collect();
    serde_json::Value::Array(items).to_string()
}

/// Build a `vgi.example_queries` JSON array (VGI515): one `{description, sql}`
/// object per example. This is the described-example carrier — unlike the native
/// `duckdb_functions().examples` column (which the vgi extension populates from
/// `Meta.examples` but drops the per-example description), it keeps a
/// human-readable description on every example so `vgi-lint` can verify it.
/// The SQL is byte-identical to the matching `Meta.examples` entry so the linter
/// dedups the two carriers and the described one wins.
pub fn example_queries_json(examples: &[(&str, &str)]) -> String {
    let items: Vec<serde_json::Value> = examples
        .iter()
        .map(|(description, sql)| serde_json::json!({ "description": description, "sql": sql }))
        .collect();
    serde_json::Value::Array(items).to_string()
}

/// Build a `vgi.result_columns_schema` JSON array (VGI307/321-323) for a table
/// function with a static result schema: one `{name,type,description}` object per
/// returned column. `type` must be a real DuckDB type and `description` non-blank.
pub fn result_columns_schema_json(columns: &[(&str, &str, &str)]) -> String {
    let items: Vec<serde_json::Value> = columns
        .iter()
        .map(
            |(name, ty, desc)| serde_json::json!({ "name": name, "type": ty, "description": desc }),
        )
        .collect();
    serde_json::Value::Array(items).to_string()
}

/// Category names for the schema's `vgi.categories` registry (VGI413). Each
/// object carries a `vgi.category` naming exactly one of these; the schema
/// declares the ordered registry via [`categories_json`].
pub const CAT_GENERIC: &str = "Generic ASN.1";
pub const CAT_SECURITY: &str = "Security Modules";

/// The ordered `vgi.categories` registry declared on schema `main` (VGI413): an
/// array of `{"name","description"}` objects, one per [`CAT_GENERIC`] /
/// [`CAT_SECURITY`]. Order is the navigation/listing order.
pub fn categories_json() -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }
    let cats = [
        (
            CAT_GENERIC,
            "Generic BER/CER/DER codec: decode, dump, walk, inventory OIDs, validate, and \
             canonicalize any ASN.1 blob, plus PEM extraction and OID name lookup.",
        ),
        (
            CAT_SECURITY,
            "Structural decoders for the named modules that ride on ASN.1 — SNMP, Kerberos, \
             LDAP, CMS/PKCS#7, PKCS#8/#12, OCSP — shredding them into JSON and joinable rows.",
        ),
    ];
    let items: Vec<String> = cats
        .iter()
        .map(|(name, desc)| {
            format!(
                "{{\"name\":\"{}\",\"description\":\"{}\"}}",
                esc(name),
                esc(desc)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the standard per-object discovery/description tags (title, doc_llm,
/// doc_md, keywords, category). `category` must name one of the schema's
/// `vgi.categories` (VGI413); use a `CAT_*` constant. `_relative_path` is
/// retained for call-site documentation only — it is no longer emitted as a
/// per-object `vgi.source_url` (catalog-only, VGI139).
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
    _relative_path: &str,
    category: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
        ("vgi.category".to_string(), category.to_string()),
    ]
}
