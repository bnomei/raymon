//! Canonical color names used throughout Raymon.
//!
//! Ray payloads can include a `"color"` field, but we only treat a small set as "official"
//! (matching the Ray UI): `green`, `yellow`, `red`, `purple`, `blue`, `grey`.
//!
//! Incoming values are normalized to lowercase and mapped into this official set.
//! Unknown values return `None`.

/// Official color names (all lowercase).
pub const OFFICIAL_COLORS: [&str; 6] = ["green", "yellow", "red", "purple", "blue", "grey"];

/// Convert an incoming color string into an official Raymon color name.
///
/// Returns `None` for unknown colors.
pub fn canonical_color_name(value: &str) -> Option<&'static str> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "green" => Some("green"),
        "yellow" | "orange" => Some("yellow"),
        "red" => Some("red"),
        "purple" | "magenta" => Some("purple"),
        "blue" | "cyan" => Some("blue"),
        "grey" | "gray" => Some("grey"),
        _ => None,
    }
}
