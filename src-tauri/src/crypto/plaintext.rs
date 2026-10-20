//! Cleanup of decrypted PGP attachments.
//!
//! A decrypted attachment is written next to its ciphertext
//! (`tdlib/documents/bhtelegram-xxx.pgp` -> `tdlib/documents/bhtelegram-xxx`, see
//! `pgp::get_plaintext_path`) so it can be opened with an external app. Those
//! plaintext copies must not outlive the session: they are wiped at startup
//! (in case of a crash), on exit and when the user hides encrypted content.

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use crate::store;

const PGP_PREFIXES: [&str; 2] = ["bhtelegram-", "ombra-chat-"];

fn documents_dir<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> PathBuf {
    let mut dir = PathBuf::from(store::get_application_folder(app));
    dir.push("tdlib");
    dir.push("documents");
    dir
}

/// A file is a decrypted plaintext copy if it has our prefix, is not itself a
/// `.pgp` file and its `.pgp` ciphertext sibling exists.
fn is_plaintext_copy(path: &Path) -> bool {
    let name = match path.file_name().and_then(|n| n.to_str()) {
        Some(n) => n,
        None => return false,
    };
    if name.ends_with(".pgp") || !PGP_PREFIXES.iter().any(|p| name.starts_with(p)) {
        return false;
    }
    let mut ciphertext = path.as_os_str().to_owned();
    ciphertext.push(".pgp");
    Path::new(&ciphertext).is_file()
}

/// Best effort overwrite before unlinking. Not a guarantee on SSDs or
/// copy-on-write filesystems, but it avoids leaving the content trivially
/// recoverable from the freed blocks.
fn shred(path: &Path) -> std::io::Result<()> {
    if let Ok(meta) = fs::metadata(path) {
        if let Ok(mut file) = OpenOptions::new().write(true).open(path) {
            let zeros = vec![0u8; 64 * 1024];
            let mut remaining = meta.len();
            while remaining > 0 {
                let n = remaining.min(zeros.len() as u64) as usize;
                if file.write_all(&zeros[..n]).is_err() {
                    break;
                }
                remaining -= n as u64;
            }
            let _ = file.sync_all();
        }
    }
    fs::remove_file(path)
}

pub fn wipe_plaintext_files_in(dir: &Path) -> Result<usize, Box<dyn Error>> {
    if !dir.is_dir() {
        return Ok(0);
    }
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_file() && is_plaintext_copy(&path) {
            match shred(&path) {
                Ok(()) => removed += 1,
                Err(e) => log::warn!("Unable to remove decrypted file: {}", e),
            }
        }
    }
    Ok(removed)
}

pub fn wipe_plaintext_files<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<usize, Box<dyn Error>> {
    let removed = wipe_plaintext_files_in(&documents_dir(app))?;
    if removed > 0 {
        log::debug!("Removed {} decrypted file(s)", removed);
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removes_only_decrypted_copies() {
        let dir = std::env::temp_dir().join(format!(
            "bhtelegram-wipe-test-{}",
            crate::crypto::utils::generate_random_string(8)
        ));
        fs::create_dir_all(&dir).unwrap();
        let touch = |name: &str| fs::write(dir.join(name), b"data").unwrap();

        touch("bhtelegram-abc.pgp");
        touch("bhtelegram-abc"); // decrypted copy -> removed
        touch("ombra-chat-old.pgp");
        touch("ombra-chat-old"); // upstream decrypted copy -> removed
        touch("bhtelegram-orphan"); // no ciphertext sibling -> kept
        touch("report.pdf.pgp");
        touch("report.pdf"); // not ours -> kept
        touch("bhtelegram-msg.txt.pgp"); // ciphertext -> kept

        assert_eq!(wipe_plaintext_files_in(&dir).unwrap(), 2);
        assert!(!dir.join("bhtelegram-abc").exists());
        assert!(!dir.join("ombra-chat-old").exists());
        assert!(dir.join("bhtelegram-abc.pgp").exists());
        assert!(dir.join("bhtelegram-orphan").exists());
        assert!(dir.join("report.pdf").exists());
        assert!(dir.join("bhtelegram-msg.txt.pgp").exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_dir_is_not_an_error() {
        let dir = std::env::temp_dir().join("bhtelegram-does-not-exist-xyz");
        assert_eq!(wipe_plaintext_files_in(&dir).unwrap(), 0);
    }
}
