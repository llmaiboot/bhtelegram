//! Local encryption at rest for ZK state (identity, ratchet sessions,
//! decrypted history). A random 256-bit data key encrypts every file; the
//! data key itself is stored wrapped with Argon2id(passphrase, salt) in a
//! single `key.bin`, so changing the passphrase rewrites one file atomically.
//! Cipher: XChaCha20-Poly1305 with a random 24-byte nonce per write and the
//! file label as associated data, so files cannot be swapped silently.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand::RngCore;
use std::fs;
use std::io::Write;
use std::path::Path;
use zeroize::Zeroizing;

const MAGIC: &[u8; 6] = b"BHZK1\0";
const NONCE_LEN: usize = 24;

pub struct Vault {
    key: Zeroizing<[u8; 32]>,
}

// Never print key material.
impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Vault(<redacted>)")
    }
}

const SALT_LEN: usize = 16;
const KEY_LABEL: &str = "data-key";

impl Vault {
    /// Loads the data key from `key_path`, or creates one on first use.
    /// A wrong passphrase fails; nothing is overwritten.
    pub fn unlock(key_path: &Path, passphrase: &str) -> Result<Self, String> {
        let next = next_path(key_path);
        match Self::unlock_one(key_path, passphrase) {
            Ok(v) => {
                // A passphrase change that never completed: forget it.
                let _ = fs::remove_file(&next);
                Ok(v)
            }
            Err(e) if next.exists() => {
                // Crash after the PGP key was switched but before key.bin was:
                // the new passphrase opens the pending file; finish the change.
                let v = Self::unlock_one(&next, passphrase).map_err(|_| e)?;
                fs::rename(&next, key_path).map_err(|e| e.to_string())?;
                Ok(v)
            }
            Err(e) => Err(e),
        }
    }

    /// Step 1 of a passphrase change: the data key wrapped with the new
    /// passphrase goes to `key.bin.next`; `key.bin` is untouched.
    pub fn prepare_rewrap(&self, key_path: &Path, new_passphrase: &str) -> Result<(), String> {
        self.wrap_to(&next_path(key_path), new_passphrase)
    }

    /// Step 2: make the new wrap current.
    pub fn commit_rewrap(key_path: &Path) -> Result<(), String> {
        fs::rename(next_path(key_path), key_path).map_err(|e| e.to_string())
    }

    pub fn abort_rewrap(key_path: &Path) {
        let _ = fs::remove_file(next_path(key_path));
    }

    fn unlock_one(key_path: &Path, passphrase: &str) -> Result<Self, String> {
        match fs::read(key_path) {
            Ok(data) => {
                if data.len() < SALT_LEN {
                    return Err("damaged key file".into());
                }
                let kek = Self::derive(passphrase, &data[..SALT_LEN])?;
                let dek = kek.open(KEY_LABEL, &data[SALT_LEN..])?;
                let key: [u8; 32] = dek[..].try_into().map_err(|_| "damaged key file")?;
                Ok(Vault { key: Zeroizing::new(key) })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let vault = Vault { key: Zeroizing::new(random_bytes::<32>()) };
                vault.wrap_to(key_path, passphrase)?;
                Ok(vault)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    /// Stores this vault's data key wrapped with a new passphrase.
    pub fn wrap_to(&self, key_path: &Path, passphrase: &str) -> Result<(), String> {
        let salt = random_bytes::<SALT_LEN>();
        let kek = Self::derive(passphrase, &salt)?;
        let mut out = salt.to_vec();
        out.extend_from_slice(&kek.seal(KEY_LABEL, self.key.as_ref())?);
        write_atomic(key_path, &out)
    }

    fn derive(passphrase: &str, salt: &[u8]) -> Result<Self, String> {
        // OWASP 2023 minimum for Argon2id; fast enough on phones (~0.3 s).
        let params = Params::new(19 * 1024, 2, 1, Some(32)).map_err(|e| e.to_string())?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = Zeroizing::new([0u8; 32]);
        argon
            .hash_password_into(passphrase.as_bytes(), salt, key.as_mut())
            .map_err(|e| e.to_string())?;
        Ok(Vault { key })
    }

    pub fn seal(&self, label: &str, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = XChaCha20Poly1305::new(self.key.as_ref().into());
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: label.as_bytes(),
                },
            )
            .map_err(|_| "encryption failed".to_string())?;
        let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn open(&self, label: &str, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        if data.len() < MAGIC.len() + NONCE_LEN || &data[..MAGIC.len()] != MAGIC {
            return Err("not a BhTelegram vault file".into());
        }
        let nonce = &data[MAGIC.len()..MAGIC.len() + NONCE_LEN];
        let cipher = XChaCha20Poly1305::new(self.key.as_ref().into());
        cipher
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: &data[MAGIC.len() + NONCE_LEN..],
                    aad: label.as_bytes(),
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| "wrong passphrase or damaged file".to_string())
    }

    pub fn write_file(&self, path: &Path, label: &str, plaintext: &[u8]) -> Result<(), String> {
        let sealed = self.seal(label, plaintext)?;
        write_atomic(path, &sealed)
    }

    pub fn read_file(&self, path: &Path, label: &str) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
        match fs::read(path) {
            Ok(data) => self.open(label, &data).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
}

fn next_path(key_path: &Path) -> std::path::PathBuf {
    key_path.with_extension("bin.next")
}

/// Unique temp file (0600) + fsync + rename + fsync of the directory, so a
/// crash or power loss leaves either the old or the new file, never a mix.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<(), String> {
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("f");
    let tmp = path.with_file_name(format!(".{}.{}.tmp", name, hex::encode(random_bytes::<6>())));
    let res = (|| -> std::io::Result<()> {
        let mut opts = fs::OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        drop(f);
        fs::rename(&tmp, path)?;
        #[cfg(unix)]
        if let Some(dir) = path.parent() {
            fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    })();
    if res.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    res.map_err(|e| e.to_string())
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip_and_label_binding() {
        let v = Vault::derive("pass", b"0123456789abcdef").unwrap();
        let sealed = v.seal("a", b"secret").unwrap();
        assert_eq!(&v.open("a", &sealed).unwrap()[..], b"secret");
        assert!(v.open("b", &sealed).is_err(), "label must be authenticated");
        let other = Vault::derive("other", b"0123456789abcdef").unwrap();
        assert!(other.open("a", &sealed).is_err());
        let mut tampered = sealed.clone();
        *tampered.last_mut().unwrap() ^= 1;
        assert!(v.open("a", &tampered).is_err());
    }

    #[test]
    fn unlock_rewrap_and_wrong_passphrase() {
        let dir = std::env::temp_dir().join(format!("bhzk-vault-{}", rand::random::<u32>()));
        fs::create_dir_all(&dir).unwrap();
        let kp = dir.join("key.bin");
        let v = Vault::unlock(&kp, "one").unwrap();
        let sealed = v.seal("x", b"data").unwrap();
        assert!(Vault::unlock(&kp, "two").is_err());
        v.wrap_to(&kp, "two").unwrap();
        assert!(Vault::unlock(&kp, "one").is_err());
        let v2 = Vault::unlock(&kp, "two").unwrap();
        assert_eq!(&v2.open("x", &sealed).unwrap()[..], b"data");
    }

    #[test]
    fn interrupted_passphrase_change_recovers() {
        let dir = std::env::temp_dir().join(format!("bhzk-rewrap-{}", rand::random::<u32>()));
        fs::create_dir_all(&dir).unwrap();
        let kp = dir.join("key.bin");
        let v = Vault::unlock(&kp, "old").unwrap();
        let sealed = v.seal("x", b"data").unwrap();
        v.prepare_rewrap(&kp, "new").unwrap();
        // crash here: both passphrases must still work
        let w = Vault::unlock(&kp, "new").unwrap(); // promotes .next
        assert_eq!(&w.open("x", &sealed).unwrap()[..], b"data");
        assert!(Vault::unlock(&kp, "old").is_err());
        // stale .next is discarded when the current passphrase works
        w.prepare_rewrap(&kp, "newer").unwrap();
        assert!(Vault::unlock(&kp, "new").is_ok());
        assert!(Vault::unlock(&kp, "newer").is_err());
    }

    #[test]
    fn debug_does_not_leak_key() {
        let v = Vault::derive("pass", b"0123456789abcdef").unwrap();
        assert_eq!(format!("{:?}", v), "Vault(<redacted>)");
    }
}
