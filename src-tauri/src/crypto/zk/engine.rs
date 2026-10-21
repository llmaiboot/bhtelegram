//! Zero-knowledge chat engine (idea and threat model from zkgram, protocol
//! replaced by the audited Olm Double Ratchet from matrix-org/vodozemac).
//!
//! Telegram is an untrusted wire: it only ever carries WordCoder text. This
//! module is pure (no Tauri, no TDLib) so it can be unit-tested end to end.
//!
//! Wire = WordCoder(b"ZK" | version | type | payload)
//!   type 1 INVITE  : ed25519(32) | curve25519(32) | one-time key(32) | sig(64)
//!   type 2 PREKEY  : Olm pre-key message
//!   type 3 MESSAGE : Olm normal message
//! Inside Olm: kind(1) | [ident] | data
//!   kind 1 TEXT    : utf-8
//!   kind 2 ACCEPT  : empty (session established)
//!   kind 3 END     : empty
//!   kind | 0x80    : ident = ed25519(32) | sig(64) over ACCEPT_CTX|my curve|their curve.
//!                    Set on every message until the peer answered, so the
//!                    receiver can bind the session to an identity whatever
//!                    message reaches it first (history is not ordered).
//!
//! Ratchet message keys are single-use (forward secrecy), so every message
//! is decrypted once on arrival and kept in an encrypted local history keyed
//! by SHA-256 of the wire bytes, the way zkgram's LocalCache does it.

use super::vault::Vault;
use super::wordcoder;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use vodozemac::olm::{
    Account, AccountPickle, OlmMessage, PreKeyMessage, Session, SessionConfig, SessionPickle,
};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};

const MAGIC: &[u8; 2] = b"ZK";
const VERSION: u8 = 1;
const T_INVITE: u8 = 1;
const T_PREKEY: u8 = 2;
const T_MESSAGE: u8 = 3;
const K_TEXT: u8 = 1;
const K_ACCEPT: u8 = 2;
const K_END: u8 = 3;
const K_IDENT: u8 = 0x80;
const IDENT_LEN: usize = 96;
const INVITE_CTX: &[u8] = b"BhTelegram-ZK-invite-v1";
const ACCEPT_CTX: &[u8] = b"BhTelegram-ZK-accept-v1";
/// Plaintext bytes per Telegram message: worst case WordCoder output for
/// chunk + Olm overhead stays below Telegram's 4096 character limit.
pub const MAX_CHUNK_BYTES: usize = 300;
/// 4096 Telegram characters / 7 (longest word + space).
#[cfg(test)]
pub const MAX_WIRE_BYTES: usize = 585;
const MAX_SESSIONS_PER_CHAT: usize = 3;
const MAX_HISTORY_PER_CHAT: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub ed25519: [u8; 32],
    pub curve25519: [u8; 32],
}

impl PeerIdentity {
    fn bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&self.ed25519);
        b[32..].copy_from_slice(&self.curve25519);
        b
    }
}

/// What a Telegram text turned out to be.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Incoming {
    /// Not ZK traffic: show as a normal message.
    NotZk,
    /// Invitation to start a ZK session. `accepted` = we already run a
    /// session with this identity.
    Invite { outgoing: bool, accepted: bool },
    Text { text: String, outgoing: bool },
    /// Session established (ACCEPT control message).
    Started { outgoing: bool },
    Ended { outgoing: bool },
    /// ZK message that cannot be read here (sent from another device, key
    /// already used, wrong session...).
    Undecryptable { outgoing: bool },
}

#[derive(Serialize, Deserialize)]
struct SessionEntry {
    pickle: SessionPickle,
    peer: PeerIdentity,
}

#[derive(Serialize, Deserialize, Default)]
struct ChatFile {
    /// Newest last. Encryption always uses the newest one.
    sessions: Vec<SessionEntry>,
    /// Identity seen first in this chat (trust on first use).
    pinned_peer: Option<PeerIdentity>,
    verified: bool,
    peer_changed: bool,
    /// hex(sha256(wire bytes)) -> decrypted result
    history: HashMap<String, Incoming>,
    history_order: Vec<String>,
}

struct ChatState {
    sessions: Vec<(Session, PeerIdentity)>,
    file: ChatFile,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChatStatus {
    /// "none" | "active"
    pub state: String,
    pub safety_number: Option<String>,
    pub verified: bool,
    pub peer_changed: bool,
    /// Decrypted messages exist locally (secret view makes sense).
    pub has_history: bool,
}

pub struct ZkEngine {
    dir: PathBuf,
    vault: Vault,
    account: Account,
    chats: HashMap<i64, ChatState>,
}

impl std::fmt::Debug for ZkEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZkEngine(<redacted>)")
    }
}

fn hex32(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn session_config() -> SessionConfig {
    SessionConfig::version_1()
}

impl ZkEngine {
    /// Opens the encrypted ZK store in `dir`, creating a new identity on
    /// first use. A wrong passphrase fails instead of overwriting data.
    pub fn open(dir: &Path, passphrase: &str) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let vault = Vault::unlock(&dir.join("key.bin"), passphrase)?;
        let id_path = dir.join("identity.bin");
        let account = match vault.read_file(&id_path, "identity")? {
            Some(data) => {
                let pickle: AccountPickle =
                    serde_json::from_slice(&data).map_err(|e| e.to_string())?;
                Account::from_pickle(pickle)
            }
            None => {
                let account = Account::new();
                let data = serde_json::to_vec(&account.pickle()).map_err(|e| e.to_string())?;
                vault.write_file(&id_path, "identity", &data)?;
                account
            }
        };
        Ok(ZkEngine {
            dir: dir.to_path_buf(),
            vault,
            account,
            chats: HashMap::new(),
        })
    }

    pub fn identity(&self) -> PeerIdentity {
        PeerIdentity {
            ed25519: *self.account.ed25519_key().as_bytes(),
            curve25519: self.account.curve25519_key().to_bytes(),
        }
    }

    fn save_account(&self) -> Result<(), String> {
        let data = serde_json::to_vec(&self.account.pickle()).map_err(|e| e.to_string())?;
        self.vault
            .write_file(&self.dir.join("identity.bin"), "identity", &data)
    }

    fn chat_path(&self, chat_id: i64) -> PathBuf {
        self.dir.join(format!("chat_{}.bin", chat_id))
    }

    fn chat(&mut self, chat_id: i64) -> Result<&mut ChatState, String> {
        if !self.chats.contains_key(&chat_id) {
            let label = format!("chat:{}", chat_id);
            let file: ChatFile = match self.vault.read_file(&self.chat_path(chat_id), &label)? {
                Some(data) => serde_json::from_slice(&data).map_err(|e| e.to_string())?,
                None => ChatFile::default(),
            };
            let sessions = file
                .sessions
                .iter()
                .map(|s| {
                    // SessionPickle is not Clone: round-trip through JSON.
                    let json = serde_json::to_vec(&s.pickle).unwrap_or_default();
                    serde_json::from_slice::<SessionPickle>(&json)
                        .map(|p| (Session::from_pickle(p), s.peer))
                        .map_err(|e| e.to_string())
                })
                .collect::<Result<Vec<_>, String>>()?;
            self.chats.insert(chat_id, ChatState { sessions, file });
        }
        Ok(self.chats.get_mut(&chat_id).unwrap())
    }

    fn save_chat(&mut self, chat_id: i64) -> Result<(), String> {
        let path = self.chat_path(chat_id);
        let label = format!("chat:{}", chat_id);
        let st = self.chats.get_mut(&chat_id).ok_or("no chat state")?;
        st.file.sessions = st
            .sessions
            .iter()
            .map(|(s, p)| SessionEntry {
                pickle: s.pickle(),
                peer: *p,
            })
            .collect();
        let data = serde_json::to_vec(&st.file).map_err(|e| e.to_string())?;
        self.vault.write_file(&path, &label, &data)
    }

    fn remember(st: &mut ChatState, key: String, value: Incoming) {
        if !st.file.history.contains_key(&key) {
            st.file.history_order.push(key.clone());
        }
        st.file.history.insert(key, value);
        while st.file.history_order.len() > MAX_HISTORY_PER_CHAT {
            let old = st.file.history_order.remove(0);
            st.file.history.remove(&old);
        }
    }

    fn add_session(st: &mut ChatState, session: Session, peer: PeerIdentity) {
        match st.file.pinned_peer {
            None => st.file.pinned_peer = Some(peer),
            Some(p) if p != peer => {
                // New identity in this chat: possible MITM or reinstall.
                st.file.pinned_peer = Some(peer);
                st.file.verified = false;
                st.file.peer_changed = true;
            }
            _ => {}
        }
        st.sessions.retain(|(_, p)| *p == peer);
        st.sessions.push((session, peer));
        while st.sessions.len() > MAX_SESSIONS_PER_CHAT {
            st.sessions.remove(0);
        }
    }

    // ---------- wire helpers ----------

    fn wrap(kind: u8, payload: &[u8]) -> (String, Vec<u8>) {
        let mut b = Vec::with_capacity(4 + payload.len());
        b.extend_from_slice(MAGIC);
        b.push(VERSION);
        b.push(kind);
        b.extend_from_slice(payload);
        (wordcoder::encode(&b), b)
    }

    fn unwrap(text: &str) -> Option<(u8, Vec<u8>)> {
        let b = wordcoder::decode(text)?;
        if b.len() < 4 || &b[..2] != MAGIC || b[2] != VERSION {
            return None;
        }
        Some((b[3], b[4..].to_vec()))
    }

    /// Cheap check used by the parser before taking any lock.
    pub fn looks_like_zk(text: &str) -> bool {
        // first two words encode "ZK"
        let mut it = text.split_whitespace();
        let a = it.next().and_then(|w| wordcoder::decode(w));
        let b = it.next().and_then(|w| wordcoder::decode(w));
        a.as_deref() == Some(&MAGIC[..1]) && b.as_deref() == Some(&MAGIC[1..])
    }

    fn ident_block(&self, peer: &PeerIdentity) -> Vec<u8> {
        let me = self.identity();
        let mut signed = Vec::new();
        signed.extend_from_slice(ACCEPT_CTX);
        signed.extend_from_slice(&me.curve25519);
        signed.extend_from_slice(&peer.curve25519);
        let sig = self.account.sign(&signed);
        let mut b = Vec::with_capacity(IDENT_LEN);
        b.extend_from_slice(&me.ed25519);
        b.extend_from_slice(&sig.to_bytes());
        b
    }

    fn encrypt_inner(&mut self, chat_id: i64, kind: u8, data: &[u8]) -> Result<String, String> {
        let (needs_ident, peer) = {
            let st = self.chat(chat_id)?;
            let (session, peer) = st
                .sessions
                .last()
                .ok_or("no active secure session in this chat")?;
            (!session.has_received_message(), *peer)
        };
        let mut plain = Vec::with_capacity(1 + IDENT_LEN + data.len());
        if needs_ident {
            plain.push(kind | K_IDENT);
            plain.extend_from_slice(&self.ident_block(&peer));
        } else {
            plain.push(kind);
        }
        plain.extend_from_slice(data);
        let st = self.chat(chat_id)?;
        let (session, _) = st.sessions.last_mut().unwrap();
        let msg = session.encrypt(&plain).map_err(|e| e.to_string())?;
        let (t, body) = msg.to_parts();
        let wire_type = if t == 0 { T_PREKEY } else { T_MESSAGE };
        let (text, bytes) = Self::wrap(wire_type, &body);
        let value = match kind {
            K_TEXT => Incoming::Text {
                text: String::from_utf8_lossy(data).into_owned(),
                outgoing: true,
            },
            K_ACCEPT => Incoming::Started { outgoing: true },
            _ => Incoming::Ended { outgoing: true },
        };
        Self::remember(st, hex32(&bytes), value);
        Ok(text)
    }

    // ---------- public API ----------

    /// Builds an invitation. It carries only public keys.
    pub fn create_invite(&mut self) -> Result<String, String> {
        self.account.generate_one_time_keys(1);
        let otk = *self
            .account
            .one_time_keys()
            .values()
            .last()
            .ok_or("unable to create one-time key")?;
        self.account.mark_keys_as_published();
        self.save_account()?;
        let id = self.identity();
        let mut signed = Vec::new();
        signed.extend_from_slice(INVITE_CTX);
        signed.extend_from_slice(&id.curve25519);
        signed.extend_from_slice(otk.as_bytes());
        let sig = self.account.sign(&signed);
        let mut payload = Vec::with_capacity(160);
        payload.extend_from_slice(&id.ed25519);
        payload.extend_from_slice(&id.curve25519);
        payload.extend_from_slice(otk.as_bytes());
        payload.extend_from_slice(&sig.to_bytes());
        Ok(Self::wrap(T_INVITE, &payload).0)
    }

    fn parse_invite(payload: &[u8]) -> Result<(PeerIdentity, Curve25519PublicKey), String> {
        if payload.len() != 160 {
            return Err("bad invite".into());
        }
        let ed: [u8; 32] = payload[..32].try_into().unwrap();
        let curve: [u8; 32] = payload[32..64].try_into().unwrap();
        let otk: [u8; 32] = payload[64..96].try_into().unwrap();
        let sig = Ed25519Signature::from_slice(&payload[96..]).map_err(|e| e.to_string())?;
        let ed_key = Ed25519PublicKey::from_slice(&ed).map_err(|e| e.to_string())?;
        let mut signed = Vec::new();
        signed.extend_from_slice(INVITE_CTX);
        signed.extend_from_slice(&curve);
        signed.extend_from_slice(&otk);
        ed_key
            .verify(&signed, &sig)
            .map_err(|_| "invite signature is invalid".to_string())?;
        Ok((
            PeerIdentity {
                ed25519: ed,
                curve25519: curve,
            },
            Curve25519PublicKey::from_bytes(otk),
        ))
    }

    /// Accepts an invitation received in `chat_id`; returns the wire text
    /// to send back (encrypted ACCEPT, an Olm pre-key message).
    pub fn accept_invite(&mut self, chat_id: i64, invite_text: &str) -> Result<String, String> {
        let (t, payload) = Self::unwrap(invite_text).ok_or("not an invitation")?;
        if t != T_INVITE {
            return Err("not an invitation".into());
        }
        let (peer, otk) = Self::parse_invite(&payload)?;
        if peer == self.identity() {
            return Err("this is your own invitation".into());
        }
        let session = self
            .account
            .create_outbound_session(
                session_config(),
                Curve25519PublicKey::from_bytes(peer.curve25519),
                otk,
            )
            .map_err(|e| e.to_string())?;
        {
            let st = self.chat(chat_id)?;
            Self::add_session(st, session, peer);
        }
        let text = self.encrypt_inner(chat_id, K_ACCEPT, &[])?;
        self.save_chat(chat_id)?;
        Ok(text)
    }

    /// Encrypts a text, split in chunks that fit one Telegram message each.
    pub fn encrypt_text(&mut self, chat_id: i64, text: &str) -> Result<Vec<String>, String> {
        let mut out = Vec::new();
        for chunk in split_utf8(text, MAX_CHUNK_BYTES) {
            out.push(self.encrypt_inner(chat_id, K_TEXT, chunk.as_bytes())?);
        }
        self.save_chat(chat_id)?;
        Ok(out)
    }

    /// Ends the session: returns the END notice to send, then forgets keys.
    pub fn end_session(&mut self, chat_id: i64) -> Result<String, String> {
        let text = self.encrypt_inner(chat_id, K_END, &[])?;
        self.chat(chat_id)?.sessions.clear();
        self.save_chat(chat_id)?;
        Ok(text)
    }

    /// Decides what a Telegram text is. Decrypts at most once; later calls
    /// for the same wire bytes are served from the encrypted history.
    pub fn process(&mut self, chat_id: i64, text: &str, outgoing: bool) -> Incoming {
        if !Self::looks_like_zk(text) {
            return Incoming::NotZk;
        }
        let Some((t, payload)) = Self::unwrap(text) else {
            return Incoming::NotZk;
        };
        let mut full = Vec::with_capacity(4 + payload.len());
        full.extend_from_slice(MAGIC);
        full.push(VERSION);
        full.push(t);
        full.extend_from_slice(&payload);
        let key = hex32(&full);

        if t == T_INVITE {
            let me = self.identity();
            return match Self::parse_invite(&payload) {
                Ok((peer, _)) => {
                    let mine = peer == me;
                    let accepted = !mine
                        && self
                            .chat(chat_id)
                            .map(|st| st.sessions.iter().any(|(_, p)| *p == peer))
                            .unwrap_or(false);
                    Incoming::Invite {
                        outgoing: mine || outgoing,
                        accepted,
                    }
                }
                Err(_) => Incoming::Undecryptable { outgoing },
            };
        }

        if let Ok(st) = self.chat(chat_id) {
            if let Some(v) = st.file.history.get(&key) {
                return v.clone();
            }
        }
        if outgoing {
            // Our own ciphertext is encrypted for the peer, not for us.
            return Incoming::Undecryptable { outgoing: true };
        }
        let result = match t {
            T_PREKEY => self.decrypt_prekey(chat_id, &payload),
            T_MESSAGE => self.decrypt_normal(chat_id, &payload),
            _ => Err("unknown type".into()),
        };
        let value = match result {
            Ok(v) => v,
            Err(e) => {
                log::warn!("ZK message in chat {} not decrypted: {}", chat_id, e);
                return Incoming::Undecryptable { outgoing: false };
            }
        };
        if let Ok(st) = self.chat(chat_id) {
            Self::remember(st, key, value.clone());
        }
        if let Err(e) = self.save_chat(chat_id) {
            log::error!("Unable to save ZK chat state: {}", e);
        }
        value
    }

    fn decrypt_prekey(&mut self, chat_id: i64, body: &[u8]) -> Result<Incoming, String> {
        let pre = PreKeyMessage::from_bytes(body).map_err(|e| e.to_string())?;
        let msg = OlmMessage::PreKey(pre.clone());
        // A peer keeps sending pre-key messages until we answer: reuse the
        // matching session first.
        {
            let st = self.chat(chat_id)?;
            let sid = pre.session_id();
            for (session, peer) in st.sessions.iter_mut() {
                if session.session_id() == sid {
                    let peer = *peer;
                    let plain = session.decrypt(&msg).map_err(|e| e.to_string())?;
                    return Self::handle_plain(st, peer, &plain, false);
                }
            }
        }
        let their_curve = pre.identity_key();
        let res = self
            .account
            .create_inbound_session(session_config(), their_curve, &pre)
            .map_err(|e| e.to_string())?;
        let p = &res.plaintext;
        if p.is_empty() || p[0] & K_IDENT == 0 || p.len() < 1 + IDENT_LEN {
            return Err("first message of a session carries no identity".into());
        }
        let ed: [u8; 32] = p[1..33].try_into().unwrap();
        let sig = Ed25519Signature::from_slice(&p[33..1 + IDENT_LEN]).map_err(|e| e.to_string())?;
        let ed_key = Ed25519PublicKey::from_slice(&ed).map_err(|e| e.to_string())?;
        let me = self.identity();
        let mut signed = Vec::new();
        signed.extend_from_slice(ACCEPT_CTX);
        signed.extend_from_slice(their_curve.as_bytes());
        signed.extend_from_slice(&me.curve25519);
        ed_key
            .verify(&signed, &sig)
            .map_err(|_| "accept signature is invalid".to_string())?;
        let peer = PeerIdentity {
            ed25519: ed,
            curve25519: their_curve.to_bytes(),
        };
        // Only now is the one-time key really spent: persist the account.
        self.save_account()?;
        let st = self.chat(chat_id)?;
        Self::add_session(st, res.session, peer);
        Self::handle_plain(st, peer, &res.plaintext, false)
    }

    fn decrypt_normal(&mut self, chat_id: i64, body: &[u8]) -> Result<Incoming, String> {
        let msg = OlmMessage::from_parts(1, body).map_err(|e| e.to_string())?;
        let st = self.chat(chat_id)?;
        let mut last_err = String::from("no session");
        for i in (0..st.sessions.len()).rev() {
            let peer = st.sessions[i].1;
            match st.sessions[i].0.decrypt(&msg) {
                Ok(plain) => return Self::handle_plain(st, peer, &plain, false),
                Err(e) => last_err = e.to_string(),
            }
        }
        Err(last_err)
    }

    fn handle_plain(
        st: &mut ChatState,
        peer: PeerIdentity,
        plain: &[u8],
        outgoing: bool,
    ) -> Result<Incoming, String> {
        let Some(&first) = plain.first() else {
            return Err("empty inner message".into());
        };
        let body = if first & K_IDENT != 0 {
            plain.get(1 + IDENT_LEN..).ok_or("short inner message")?
        } else {
            &plain[1..]
        };
        match first & !K_IDENT {
            K_TEXT => Ok(Incoming::Text {
                text: String::from_utf8_lossy(body).into_owned(),
                outgoing,
            }),
            K_ACCEPT => Ok(Incoming::Started { outgoing }),
            K_END => {
                st.sessions.retain(|(_, p)| *p != peer);
                Ok(Incoming::Ended { outgoing })
            }
            _ => Err("unknown inner message".into()),
        }
    }

    pub fn status(&mut self, chat_id: i64) -> Result<ChatStatus, String> {
        let me = self.identity();
        let st = self.chat(chat_id)?;
        let active = st.sessions.last().map(|(_, p)| *p);
        Ok(ChatStatus {
            state: if active.is_some() { "active" } else { "none" }.into(),
            safety_number: active.map(|p| safety_number(&me, &p)),
            verified: st.file.verified,
            peer_changed: st.file.peer_changed,
            has_history: st
                .file
                .history
                .values()
                .any(|v| matches!(v, Incoming::Text { .. })),
        })
    }

    pub fn set_verified(&mut self, chat_id: i64, verified: bool) -> Result<(), String> {
        let st = self.chat(chat_id)?;
        if st.sessions.is_empty() {
            return Err("no active secure session".into());
        }
        st.file.verified = verified;
        if verified {
            st.file.peer_changed = false;
        }
        self.save_chat(chat_id)
    }

    /// Changes the passphrase: only the wrapped data key is rewritten
    /// (one atomic file write), so a crash cannot leave data unreadable.
    pub fn rekey(&mut self, new_passphrase: &str) -> Result<(), String> {
        self.vault.wrap_to(&self.dir.join("key.bin"), new_passphrase)
    }
}

/// 60-digit number both sides compare over another channel (Signal-style).
/// Identical on both devices: the two identities are sorted first.
pub fn safety_number(a: &PeerIdentity, b: &PeerIdentity) -> String {
    let (x, y) = if a.bytes() <= b.bytes() { (a, b) } else { (b, a) };
    let mut h = Sha512::new();
    h.update(b"BhTelegram-ZK-safety-v1");
    h.update(x.bytes());
    h.update(y.bytes());
    let d = h.finalize();
    (0..12)
        .map(|i| {
            let c = &d[i * 5..i * 5 + 5];
            let n = c.iter().fold(0u64, |acc, b| (acc << 8) | *b as u64);
            format!("{:05}", n % 100_000)
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn split_utf8(text: &str, max: usize) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while rest.len() > max {
        let mut cut = max;
        while !rest.is_char_boundary(cut) {
            cut -= 1;
        }
        out.push(&rest[..cut]);
        rest = &rest[cut..];
    }
    if !rest.is_empty() || out.is_empty() {
        out.push(rest);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "bhzk-{}-{}-{}",
            name,
            std::process::id(),
            rand::random::<u32>()
        ));
        let _ = fs::remove_dir_all(&d);
        d
    }

    // Alice and Bob talk in "chat 1" on their side (chat ids differ in
    // reality; each engine uses its own id for the peer).
    fn pair() -> (ZkEngine, ZkEngine, PathBuf, PathBuf) {
        let (da, db) = (tmp("a"), tmp("b"));
        let a = ZkEngine::open(&da, "alice-pass").unwrap();
        let b = ZkEngine::open(&db, "bob-pass").unwrap();
        (a, b, da, db)
    }

    fn handshake(a: &mut ZkEngine, b: &mut ZkEngine) {
        let invite = a.create_invite().unwrap();
        assert_eq!(
            b.process(1, &invite, false),
            Incoming::Invite { outgoing: false, accepted: false }
        );
        assert_eq!(
            a.process(1, &invite, true),
            Incoming::Invite { outgoing: true, accepted: false }
        );
        let accept = b.accept_invite(1, &invite).unwrap();
        assert_eq!(b.process(1, &invite, false), Incoming::Invite { outgoing: false, accepted: true });
        assert_eq!(a.process(1, &accept, false), Incoming::Started { outgoing: false });
        assert_eq!(b.process(1, &accept, true), Incoming::Started { outgoing: true });
    }

    #[test]
    fn full_conversation_and_safety_numbers() {
        let (mut a, mut b, _, _) = pair();
        handshake(&mut a, &mut b);
        let sa = a.status(1).unwrap();
        let sb = b.status(1).unwrap();
        assert_eq!(sa.state, "active");
        assert_eq!(sa.safety_number, sb.safety_number);
        assert_eq!(sa.safety_number.as_ref().unwrap().len(), 12 * 5 + 11);
        assert!(!sa.has_history);

        // Bob talks first (still pre-key messages), then Alice, then both.
        let m1 = b.encrypt_text(1, "привет").unwrap();
        let m2 = b.encrypt_text(1, "второе").unwrap();
        assert!(m1[0].split(' ').all(|w| wordcoder::decode(w).is_some()));
        // out of order delivery
        assert_eq!(a.process(1, &m2[0], false), Incoming::Text { text: "второе".into(), outgoing: false });
        assert_eq!(a.process(1, &m1[0], false), Incoming::Text { text: "привет".into(), outgoing: false });
        let r = a.encrypt_text(1, "hi bob").unwrap();
        assert_eq!(b.process(1, &r[0], false), Incoming::Text { text: "hi bob".into(), outgoing: false });
        for i in 0..5 {
            let x = a.encrypt_text(1, &format!("a{}", i)).unwrap();
            let y = b.encrypt_text(1, &format!("b{}", i)).unwrap();
            assert_eq!(b.process(1, &x[0], false), Incoming::Text { text: format!("a{}", i), outgoing: false });
            assert_eq!(a.process(1, &y[0], false), Incoming::Text { text: format!("b{}", i), outgoing: false });
        }
        // re-reading history: served from cache, own messages readable
        assert_eq!(a.process(1, &m1[0], false), Incoming::Text { text: "привет".into(), outgoing: false });
        assert_eq!(b.process(1, &m1[0], true), Incoming::Text { text: "привет".into(), outgoing: true });
        assert!(a.status(1).unwrap().has_history);
        // normal text untouched
        assert_eq!(a.process(1, "обычное сообщение", false), Incoming::NotZk);
    }

    #[test]
    fn state_survives_restart_and_wrong_passphrase_fails() {
        let (mut a, mut b, da, db) = pair();
        handshake(&mut a, &mut b);
        let m = b.encrypt_text(1, "до перезапуска").unwrap();
        assert!(matches!(a.process(1, &m[0], false), Incoming::Text { .. }));
        drop(a);
        drop(b);
        assert!(ZkEngine::open(&da, "wrong").is_err());
        let mut a = ZkEngine::open(&da, "alice-pass").unwrap();
        let mut b = ZkEngine::open(&db, "bob-pass").unwrap();
        assert_eq!(a.process(1, &m[0], false), Incoming::Text { text: "до перезапуска".into(), outgoing: false });
        let r = a.encrypt_text(1, "после").unwrap();
        assert_eq!(b.process(1, &r[0], false), Incoming::Text { text: "после".into(), outgoing: false });
    }

    #[test]
    fn files_on_disk_contain_no_plaintext() {
        let (mut a, mut b, da, _) = pair();
        handshake(&mut a, &mut b);
        let m = b.encrypt_text(1, "SUPERSECRETWORD").unwrap();
        a.process(1, &m[0], false);
        for e in fs::read_dir(&da).unwrap() {
            let data = fs::read(e.unwrap().path()).unwrap();
            assert!(!String::from_utf8_lossy(&data).contains("SUPERSECRETWORD"));
        }
    }

    #[test]
    fn tampered_and_foreign_messages_are_rejected() {
        let (mut a, mut b, _, _) = pair();
        handshake(&mut a, &mut b);
        let m = b.encrypt_text(1, "x").unwrap();
        let mut bytes = wordcoder::decode(&m[0]).unwrap();
        let n = bytes.len();
        bytes[n - 1] ^= 1;
        let bad = wordcoder::encode(&bytes);
        assert_eq!(a.process(1, &bad, false), Incoming::Undecryptable { outgoing: false });
        // Eve, who has never shaken hands, cannot read it
        let mut eve = ZkEngine::open(&tmp("e"), "eve").unwrap();
        assert_eq!(eve.process(1, &m[0], false), Incoming::Undecryptable { outgoing: false });
        // forged invite signature
        let inv = a.create_invite().unwrap();
        let mut ib = wordcoder::decode(&inv).unwrap();
        ib[10] ^= 1;
        assert!(b.accept_invite(2, &wordcoder::encode(&ib)).is_err());
    }

    #[test]
    fn key_change_is_flagged_and_end_session_works() {
        let (mut a, mut b, _, _) = pair();
        handshake(&mut a, &mut b);
        a.set_verified(1, true).unwrap();
        assert!(a.status(1).unwrap().verified);
        // Bob "reinstalls": new identity in the same chat
        let mut b2 = ZkEngine::open(&tmp("b2"), "bob2").unwrap();
        handshake(&mut a, &mut b2);
        let st = a.status(1).unwrap();
        assert!(st.peer_changed);
        assert!(!st.verified);
        let end = a.end_session(1).unwrap();
        assert_eq!(b2.process(1, &end, false), Incoming::Ended { outgoing: false });
        assert_eq!(a.status(1).unwrap().state, "none");
        assert_eq!(b2.status(1).unwrap().state, "none");
        assert!(a.encrypt_text(1, "x").is_err());
        drop(b);
    }

    #[test]
    fn long_text_is_chunked_within_telegram_limit() {
        let (mut a, mut b, _, _) = pair();
        handshake(&mut a, &mut b);
        let long: String = "щ".repeat(1500); // 3000 bytes
        let parts = b.encrypt_text(1, &long).unwrap();
        assert!(parts.len() >= 8);
        let mut joined = String::new();
        for p in &parts {
            assert!(p.chars().count() <= 4096, "{} chars", p.chars().count());
            assert!(wordcoder::decode(p).unwrap().len() <= MAX_WIRE_BYTES);
            if let Incoming::Text { text, .. } = a.process(1, p, false) {
                joined.push_str(&text);
            }
        }
        assert_eq!(joined, long);
    }

    #[test]
    fn text_arriving_before_accept_still_opens_session() {
        // Chat history is loaded newest first: the inviter may see Bob's
        // first text before his ACCEPT.
        let (mut a, mut b, _, _) = pair();
        let invite = a.create_invite().unwrap();
        let accept = b.accept_invite(1, &invite).unwrap();
        let t = b.encrypt_text(1, "first").unwrap();
        assert_eq!(a.process(1, &t[0], false), Incoming::Text { text: "first".into(), outgoing: false });
        assert_eq!(a.process(1, &accept, false), Incoming::Started { outgoing: false });
        assert_eq!(a.status(1).unwrap().state, "active");
    }

    #[test]
    fn rekey_keeps_data() {
        let (mut a, mut b, da, _) = pair();
        handshake(&mut a, &mut b);
        let m = b.encrypt_text(1, "keep").unwrap();
        a.process(1, &m[0], false);
        a.rekey("new-pass").unwrap();
        drop(a);
        assert!(ZkEngine::open(&da, "alice-pass").is_err());
        let mut a = ZkEngine::open(&da, "new-pass").unwrap();
        assert_eq!(a.process(1, &m[0], false), Incoming::Text { text: "keep".into(), outgoing: false });
    }

    #[test]
    fn split_respects_char_boundaries() {
        let s = "aяbя".repeat(100);
        for part in split_utf8(&s, 7) {
            assert!(part.len() <= 7);
        }
        assert_eq!(split_utf8(&s, 7).concat(), s);
        assert_eq!(split_utf8("", 7), vec![""]);
    }
}
