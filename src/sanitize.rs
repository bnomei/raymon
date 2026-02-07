use crate::raymon_core::Entry;
use serde_json::Value;

pub fn sanitize_entry(entry: &mut Entry) {
    for payload in &mut entry.payloads {
        sanitize_value(&mut payload.content);
    }
}

fn sanitize_value(value: &mut Value) {
    match value {
        Value::String(text) => {
            if let Some(cleaned) = sanitize_symfony_var_dumper_html(text) {
                *text = cleaned;
            }
        }
        Value::Array(items) => {
            for item in items {
                sanitize_value(item);
            }
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                sanitize_value(item);
            }
        }
        _ => {}
    }
}

fn sanitize_symfony_var_dumper_html(input: &str) -> Option<String> {
    if !looks_like_symfony_var_dumper_html(input) {
        return None;
    }

    let mut cleaned = strip_html_tag_blocks(input, "script");
    cleaned = strip_html_tag_blocks(&cleaned, "style");
    cleaned = strip_html_tags(&cleaned);
    cleaned = decode_html_entities_lossy(&cleaned);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn looks_like_symfony_var_dumper_html(input: &str) -> bool {
    let trimmed = input.trim_start();
    if trimmed.starts_with("<script") && trimmed.contains("Sfdump") && trimmed.contains("sf-dump") {
        return true;
    }
    if trimmed.starts_with("<pre") && trimmed.contains("sf-dump") {
        return true;
    }
    input.contains("sf-dump") && input.contains("Sfdump")
}

fn strip_html_tag_blocks(input: &str, tag: &str) -> String {
    let open_tag = format!("<{tag}");
    let close_tag = format!("</{tag}>");
    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;

    while let Some(rel_start) = input[cursor..].find(&open_tag) {
        let start = cursor + rel_start;
        out.push_str(&input[cursor..start]);

        let Some(rel_open_end) = input[start..].find('>') else {
            cursor = input.len();
            break;
        };
        let open_end = start + rel_open_end + 1;

        let Some(rel_close) = input[open_end..].find(&close_tag) else {
            cursor = input.len();
            break;
        };
        cursor = open_end + rel_close + close_tag.len();
    }

    out.push_str(&input[cursor..]);
    out
}

fn strip_html_tags(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' if in_tag => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

fn decode_html_entities_lossy(input: &str) -> String {
    fn decode_entity(entity: &str) -> Option<char> {
        match entity {
            "nbsp" => Some(' '),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "amp" => Some('&'),
            "apos" => Some('\''),
            "#039" | "#39" => Some('\''),
            _ if entity.starts_with("#x") || entity.starts_with("#X") => {
                let value = u32::from_str_radix(&entity[2..], 16).ok()?;
                char::from_u32(value)
            }
            _ if entity.starts_with('#') => {
                let value = entity[1..].parse::<u32>().ok()?;
                char::from_u32(value)
            }
            _ => None,
        }
    }

    let mut out = String::with_capacity(input.len());
    let mut cursor = 0usize;

    while let Some(rel_start) = input[cursor..].find('&') {
        let start = cursor + rel_start;
        out.push_str(&input[cursor..start]);

        let Some(rel_end) = input[start..].find(';') else {
            out.push_str(&input[start..]);
            return out;
        };
        let end = start + rel_end;
        let entity = &input[start + 1..end];

        if let Some(ch) = decode_entity(entity) {
            out.push(ch);
        } else {
            out.push_str(&input[start..=end]);
        }

        cursor = end + 1;
    }

    out.push_str(&input[cursor..]);
    out
}

#[cfg(test)]
mod tests {
    use super::sanitize_entry;
    use crate::raymon_core::{Entry, Origin, Payload, Screen};
    use serde_json::json;

    fn origin() -> Origin {
        Origin {
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: Some(Screen::new("proj:host:default")),
            session_id: None,
            function_name: None,
            file: None,
            line_number: None,
        }
    }

    fn entry_with_value(value: &str) -> Entry {
        Entry {
            uuid: "uuid".to_string(),
            received_at: 0,
            project: "proj".to_string(),
            host: "host".to_string(),
            screen: Screen::new("proj:host:default"),
            session_id: None,
            payloads: vec![Payload { r#type: "log".to_string(), content: json!({ "values": [value] }), origin: origin() }],
        }
    }

    #[test]
    fn sanitizes_symfony_var_dumper_html() {
        let dump = r#"<script> Sfdump = window.Sfdump || (function () {})</script>
<pre class=sf-dump id=sf-dump-1 data-indent-pad="  ">
<span class=sf-dump-note>array:2</span> [<samp>
  <span class=sf-dump-index>0</span> => <span class=sf-dump-num>12</span>
  <span class=sf-dump-index>1</span> => <span class=sf-dump-num>3</span> <span>&#9654;</span>
</samp>]
</pre><script>Sfdump(\"sf-dump-1\")</script>"#;

        let mut entry = entry_with_value(dump);
        sanitize_entry(&mut entry);

        let sanitized = entry.payloads[0]
            .content
            .get("values")
            .and_then(|value| value.as_array())
            .and_then(|values| values.first())
            .and_then(|value| value.as_str())
            .expect("sanitized dump value");

        assert!(sanitized.contains("array:2"));
        assert!(sanitized.contains("0 => 12"));
        assert!(sanitized.contains("1 => 3"));
        assert!(sanitized.contains('▶'));
        assert!(!sanitized.contains("Sfdump = window.Sfdump"));
        assert!(!sanitized.contains("<span"));
        assert!(!sanitized.contains("<script"));
        assert!(!sanitized.contains("sf-dump"));
    }

    #[test]
    fn leaves_other_html_strings_alone() {
        let html = "<b>hi</b>";
        let mut entry = entry_with_value(html);
        sanitize_entry(&mut entry);
        let sanitized = entry.payloads[0]
            .content
            .get("values")
            .and_then(|value| value.as_array())
            .and_then(|values| values.first())
            .and_then(|value| value.as_str())
            .expect("html value");
        assert_eq!(sanitized, html);
    }
}
