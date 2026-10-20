//! Architecture guard borrowed from zkgram: the layer that holds keys and
//! plaintext (`src/crypto`) must not talk to Telegram, and the transport layer
//! (`src/telegram`) must not touch keys or plaintext. Only `commands`/`messages`
//! may wire the two together. A bug in TDLib handling then cannot reach keys.

use std::{fs, path::Path};

fn rust_sources(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            out.extend(rust_sources(&path));
        } else if path.extension().map(|e| e == "rs").unwrap_or(false) {
            let code: String = fs::read_to_string(&path)
                .unwrap()
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
                .collect::<Vec<_>>()
                .join("\n");
            out.push((path.display().to_string(), code));
        }
    }
    out
}

fn assert_layer_does_not_use(layer: &str, forbidden: &[&str]) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(layer);
    for (file, code) in rust_sources(&dir) {
        for f in forbidden {
            assert!(
                !code.contains(f),
                "{} uses `{}`: layer `{}` must stay isolated",
                file,
                f,
                layer
            );
        }
    }
}

#[test]
fn crypto_layer_does_not_know_telegram() {
    assert_layer_does_not_use("crypto", &["tdlib::", "crate::telegram", "crate::commands"]);
}

#[test]
fn telegram_layer_does_not_know_crypto() {
    assert_layer_does_not_use("telegram", &["crate::crypto", "pgp::"]);
}
