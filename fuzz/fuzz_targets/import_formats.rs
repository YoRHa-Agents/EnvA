#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<serde_json::Value>(data);
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = serde_yaml::from_str::<serde_yaml::Value>(text);
        for line in text.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                let _ = trimmed.split_once('=');
            }
        }
    }
});
