//! Canonical fingerprint of a configuration received from the proxy.
//!
//! The proxy sends an agent's `config { }` block on every connection (each
//! pooled connection at startup and every reconnect), so the same document
//! arrives many times. The fingerprint lets `on_configure` recognise a repeat
//! and leave runtime state alone, and it is what gets logged instead of the
//! configuration itself.

use serde_json::Value;

/// FNV-1a over a canonical serialisation of `value` (object keys sorted at
/// every level), so key order does not change the result. Stable across
/// processes and releases, unlike `DefaultHasher`.
pub fn config_fingerprint(value: &Value) -> u64 {
    let mut canonical = String::new();
    write_canonical(value, &mut canonical);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in canonical.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    hash
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(key.clone()).to_string());
                out.push(':');
                write_canonical(&map[key], out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_does_not_matter() {
        let a = json!({"a": 1, "b": {"x": true, "y": [1, 2]}});
        let b = json!({"b": {"y": [1, 2], "x": true}, "a": 1});
        assert_eq!(config_fingerprint(&a), config_fingerprint(&b));
    }

    #[test]
    fn values_matter() {
        assert_ne!(
            config_fingerprint(&json!({"a": 1})),
            config_fingerprint(&json!({"a": 2}))
        );
        assert_ne!(
            config_fingerprint(&json!({"a": [1, 2]})),
            config_fingerprint(&json!({"a": [2, 1]}))
        );
    }
}
