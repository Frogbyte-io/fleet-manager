//! A small structural check of a JSON answer against the checked-in `OpenAPI`
//! document (`packages/api-client/openapi.json`), so a test can say "this is
//! exactly what the API documents" without a schema-validation dependency.
//! Included with `#[path]`; it is test support, not a test.
//!
//! It checks what drifts in practice: every key of an object is a documented
//! property, every required property is present, every value has a documented
//! type, and a closed enum holds a listed value. `$ref`, `oneOf`, `anyOf` and
//! `allOf` are followed.

#![allow(dead_code)]

use serde_json::Value;

pub const OPENAPI: &str = include_str!("../../../../packages/api-client/openapi.json");

pub fn spec() -> Value {
    serde_json::from_str(OPENAPI).expect("the OpenAPI document is JSON")
}

/// Checks `value` against the named component schema.
pub fn assert_matches_schema(spec: &Value, schema: &str, value: &Value) {
    let root = &spec["components"]["schemas"][schema];
    assert!(root.is_object(), "the document has no schema {schema}");
    if let Err(problem) = check(spec, root, value, schema) {
        panic!("{schema} does not match the OpenAPI document: {problem}\n{value:#}");
    }
}

fn resolve<'a>(spec: &'a Value, schema: &'a Value) -> &'a Value {
    match schema.get("$ref").and_then(Value::as_str) {
        Some(reference) => {
            let name = reference
                .strip_prefix("#/components/schemas/")
                .unwrap_or_else(|| panic!("unsupported reference {reference}"));
            &spec["components"]["schemas"][name]
        }
        None => schema,
    }
}

fn type_matches(kind: &str, value: &Value) -> bool {
    match kind {
        "null" => value.is_null(),
        "string" => value.is_string(),
        "integer" => value.is_i64() || value.is_u64(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        other => panic!("unsupported type {other}"),
    }
}

fn check(spec: &Value, schema: &Value, value: &Value, at: &str) -> Result<(), String> {
    let schema = resolve(spec, schema);
    for key in ["oneOf", "anyOf"] {
        if let Some(alternatives) = schema.get(key).and_then(Value::as_array) {
            let problems: Vec<String> = alternatives
                .iter()
                .map(|alternative| check(spec, alternative, value, at))
                .filter_map(Result::err)
                .collect();
            return if problems.len() < alternatives.len() {
                Ok(())
            } else {
                Err(format!(
                    "{at}: no alternative matches ({})",
                    problems.join("; ")
                ))
            };
        }
    }
    if let Some(all) = schema.get("allOf").and_then(Value::as_array) {
        for part in all {
            check(spec, part, value, at)?;
        }
    }
    if let Some(kind) = schema.get("type") {
        let kinds: Vec<&str> = match kind {
            Value::String(kind) => vec![kind.as_str()],
            Value::Array(kinds) => kinds.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !kinds.iter().any(|kind| type_matches(kind, value)) {
            return Err(format!("{at}: {value} is not of type {kinds:?}"));
        }
    }
    if let Some(allowed) = schema.get("enum").and_then(Value::as_array)
        && !allowed.contains(value)
    {
        return Err(format!("{at}: {value} is not one of {allowed:?}"));
    }
    if let Some(object) = value.as_object()
        && let Some(properties) = schema.get("properties").and_then(Value::as_object)
    {
        for (key, member) in object {
            let Some(property) = properties.get(key) else {
                return Err(format!("{at}.{key} is not a documented property"));
            };
            check(spec, property, member, &format!("{at}.{key}"))?;
        }
        for required in schema
            .get("required")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
        {
            if !object.contains_key(required) {
                return Err(format!("{at}.{required} is required and missing"));
            }
        }
    }
    if let Some(items) = value.as_array()
        && let Some(item_schema) = schema.get("items")
    {
        for (index, item) in items.iter().enumerate() {
            check(spec, item_schema, item, &format!("{at}[{index}]"))?;
        }
    }
    Ok(())
}
