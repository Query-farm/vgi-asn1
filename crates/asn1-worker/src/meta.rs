//! Shared helpers for the per-object discovery/description metadata the
//! `vgi-lint` strict profile expects on every function and table.
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted here: it belongs on
//! the catalog object only (VGI139); the catalog's `source_url` already points at
//! the repo.

/// Encode comma-separated keywords as the JSON array of strings `vgi.keywords`
/// requires (VGI138).
pub fn keywords_json(keywords: &str) -> String {
    let items: Vec<String> = keywords
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        .map(|k| {
            let escaped = k.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the `vgi.agent_test_tasks` JSON value run by `vgi-lint simulate`.
pub fn agent_test_tasks_json(tasks: &[(&str, &str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = tasks
        .iter()
        .map(|(name, prompt, reference_sql)| {
            format!(
                "{{\"name\":\"{}\",\"prompt\":\"{}\",\"reference_sql\":\"{}\"}}",
                esc(name),
                esc(prompt),
                esc(reference_sql)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Category names for the schema's `vgi.categories` registry (VGI413). Each
/// object carries a `vgi.category` naming exactly one of these; the schema
/// declares the ordered registry via [`categories_json`].
pub const CAT_GENERIC: &str = "Generic ASN.1";
pub const CAT_SECURITY: &str = "Security Modules";
pub const CAT_DIAGNOSTICS: &str = "Diagnostics";

/// The ordered `vgi.categories` registry declared on schema `main` (VGI413): an
/// array of `{"name","description"}` objects, one per [`CAT_GENERIC`] /
/// [`CAT_SECURITY`] / [`CAT_DIAGNOSTICS`]. Order is the navigation/listing order.
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
        (
            CAT_DIAGNOSTICS,
            "Operational introspection of the running worker, such as its version string.",
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
