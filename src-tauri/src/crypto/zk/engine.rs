//! Zero-knowledge chat engine (idea and threat model from zkgram, protocol
//! replaced by the audited Olm Double Ratchet from matrix-org/vodozemac).
//!
//! Telegram is an untrusted wire: it only ever carries WordCoder text. This
//! module is pure (no Tauri, no TDLib) so it can be unit-tested end to end.
//!
//! Wire = WordCoder(b"ZK" | version | type | payload)
//!   type 1 INVITE  : ed25519(32) | curve25519(32) | one-time key(32) |
//!                    telegram user id(8) | sig(64) over INVITE_CTX|curve|otk|tg id
//!   type 2 PREKEY  : Olm pre-key message
//!   type 3 MESSAGE : Olm normal message
//! Inside Olm: kind(1) | [ident] | data
//!   kind 1 TEXT    : utf-8
//!   kind 2 ACCEPT  : empty (session established)
//!   kind 3 END     : empty
//!   kind 4 FILE    : flags(1) | file key(32). Sent as the caption of a
//!                    Telegram document whose content is `seal_file` output
//!                    (XChaCha20-Poly1305, name/mime/caption inside).
//!   kind | 0x80    : ident = ed25519(32) | sig(64) over
//!                    ACCEPT_CTX|my curve|their curve|my tg id|their tg id.
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
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use vodozemac::olm::{
    Account, AccountPickle, OlmMessage, PreKeyMessage, Session, SessionConfig, SessionPickle,
};
use vodozemac::{Curve25519PublicKey, Ed25519PublicKey, Ed25519Signature};

const MAGIC: &[u8; 2] = b"ZK";
const VERSION: u8 = 2;
const T_INVITE: u8 = 1;
const T_PREKEY: u8 = 2;
const T_MESSAGE: u8 = 3;
const K_TEXT: u8 = 1;
const K_ACCEPT: u8 = 2;
const K_END: u8 = 3;
const K_FILE: u8 = 4;
const K_IDENT: u8 = 0x80;
pub const FILE_FLAG_VOICE: u8 = 1;
/// Telegram caption limit (characters) for non-premium accounts.
pub const MAX_CAPTION_CHARS: usize = 1024;
const FILE_MAGIC: &[u8; 6] = b"BHZF1\0";
const FILE_AAD: &[u8] = b"BhTelegram-ZK-file-v1";
const IDENT_LEN: usize = 96;
const INVITE_CTX: &[u8] = b"BhTelegram-ZK-invite-v2";
/// ed25519 | curve25519 | one-time key | tg id | signature
const INVITE_LEN: usize = 32 + 32 + 32 + 8 + 64;
const ACCEPT_CTX: &[u8] = b"BhTelegram-ZK-accept-v2";
/// Plaintext bytes per Telegram message: worst case WordCoder output for
/// chunk + Olm overhead stays below Telegram's 4096 character limit.
pub const MAX_CHUNK_BYTES: usize = 300;
/// 4096 Telegram characters / 7 (longest word + space).
#[cfg(test)]
pub const MAX_WIRE_BYTES: usize = 585;
const MAX_SESSIONS_PER_CHAT: usize = 4;
const MAX_HISTORY_PER_CHAT: usize = 10_000;

/// Long-term identity of a peer: Olm keys plus the Telegram account that
/// signed them (binds the session to a Telegram user, so a third party
/// cannot relay or forward handshake messages between other chats).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerIdentity {
    pub ed25519: [u8; 32],
    pub curve25519: [u8; 32],
    #[serde(default)]
    pub tg_id: i64,
}

impl PeerIdentity {
    fn bytes(&self) -> [u8; 64] {
        let mut b = [0u8; 64];
        b[..32].copy_from_slice(&self.ed25519);
        b[32..].copy_from_slice(&self.curve25519);
        b
    }
    fn same_keys(&self, o: &PeerIdentity) -> bool {
        self.ed25519 == o.ed25519 && self.curve25519 == o.curve25519
    }
}

/// Where a Telegram message came from.
#[derive(Clone, Copy, Debug)]
pub struct Envelope {
    pub chat_id: i64,
    /// Telegram message id, 0 if unknown (disables replay detection).
    pub message_id: i64,
    /// Telegram user id of the sender (0 for channels / anonymous).
    pub sender_id: i64,
    pub outgoing: bool,
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
    /// Encrypted attachment: the key travels in the ratchet, the content in
    /// the Telegram document.
    File { key: [u8; 32], flags: u8, outgoing: bool },
    /// ZK message that cannot be read here (sent from another device, key
    /// already used, replayed, wrong sender...).
    Undecryptable { outgoing: bool },
}

impl Incoming {
    fn outgoing(&self) -> Option<bool> {
        match self {
            Incoming::NotZk => None,
            Incoming::Invite { outgoing, .. }
            | Incoming::Text { outgoing, .. }
            | Incoming::Started { outgoing }
            | Incoming::Ended { outgoing }
            | Incoming::File { outgoing, .. }
            | Incoming::Undecryptable { outgoing } => Some(*outgoing),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct SessionEntry {
    pickle: SessionPickle,
    peer: PeerIdentity,
}

#[derive(Serialize, Deserialize, Default)]
struct ChatFile {
    /// Most recently used last.
    sessions: Vec<SessionEntry>,
    /// Identity trusted in this chat (trust on first use, then explicit).
    pinned_peer: Option<PeerIdentity>,
    /// Identity that was trusted before `peer_changed` was raised.
    #[serde(default)]
    previous_peer: Option<PeerIdentity>,
    verified: bool,
    /// A new identity appeared: sending is blocked until the user accepts
    /// or rejects it.
    peer_changed: bool,
    /// hex(sha256(wire bytes)) -> decrypted result
    history: HashMap<String, Incoming>,
    history_order: VecDeque<String>,
    /// hex(sha256(wire bytes)) -> Telegram message id it was first seen in
    /// (incoming only): the same ciphertext in another message is a replay.
    #[serde(default)]
    history_ids: HashMap<String, i64>,
}

struct ChatState {
    sessions: Vec<(Session, PeerIdentity)>,
    file: ChatFile,
}

impl ChatState {
    /// Session used for sending: the newest one with the trusted identity.
    fn active_index(&self) -> Option<usize> {
        let pinned = self.file.pinned_peer?;
        self.sessions.iter().rposition(|(_, p)| *p == pinned)
    }
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
    my_tg_id: i64,
    chats: HashMap<i64, ChatState>,
}

impl std::fmt::Debug for ZkEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ZkEngine(<redacted>)")
    }
}

impl Drop for ZkEngine {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for st in self.chats.values_mut() {
            for v in st.file.history.values_mut() {
                match v {
                    Incoming::Text { text, .. } => text.zeroize(),
                    Incoming::File { key, .. } => key.zeroize(),
                    _ => {}
                }
            }
        }
    }
}

fn hex32(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

fn session_config() -> SessionConfig {
    // version_2 (full MAC) is still behind vodozemac's experimental feature.
    SessionConfig::version_1()
}

fn ident_signed(sender_curve: &[u8; 32], receiver_curve: &[u8; 32], sender_tg: i64, receiver_tg: i64) -> Vec<u8> {
    let mut v = Vec::with_capacity(ACCEPT_CTX.len() + 80);
    v.extend_from_slice(ACCEPT_CTX);
    v.extend_from_slice(sender_curve);
    v.extend_from_slice(receiver_curve);
    v.extend_from_slice(&sender_tg.to_be_bytes());
    v.extend_from_slice(&receiver_tg.to_be_bytes());
    v
}

impl ZkEngine {
    /// Opens the encrypted ZK store in `dir`, creating a new identity on
    /// first use. A wrong passphrase fails instead of overwriting data.
    /// `my_tg_id` is the Telegram user id of this account.
    pub fn open(dir: &Path, passphrase: &str, my_tg_id: i64) -> Result<Self, String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let key_path = dir.join("key.bin");
        let id_path = dir.join("identity.bin");
        if !key_path.exists() && id_path.exists() {
            return Err("ZK key file is missing: refusing to create a new one over existing data".into());
        }
        let vault = Vault::unlock(&key_path, passphrase)?;
        let account = match vault.read_file(&id_path, "identity")? {
            Some(data) => {
                let pickle: AccountPickle =
                    serde_json::from_slice(&data).map_err(|e| e.to_string())?;
                Account::from_pickle(pickle)
            }
            None => {
                let account = Account::new();
                let data = zeroize::Zeroizing::new(
                    serde_json::to_vec(&account.pickle()).map_err(|e| e.to_string())?,
                );
                vault.write_file(&id_path, "identity", &data)?;
                account
            }
        };
        Ok(ZkEngine {
            dir: dir.to_path_buf(),
            vault,
            account,
            my_tg_id,
            chats: HashMap::new(),
        })
    }

    pub fn set_my_tg_id(&mut self, id: i64) {
        self.my_tg_id = id;
    }

    pub fn identity(&self) -> PeerIdentity {
        PeerIdentity {
            ed25519: *self.account.ed25519_key().as_bytes(),
            curve25519: self.account.curve25519_key().to_bytes(),
            tg_id: self.my_tg_id,
        }
    }

    fn save_account(&self) -> Result<(), String> {
        let data = zeroize::Zeroizing::new(
            serde_json::to_vec(&self.account.pickle()).map_err(|e| e.to_string())?,
        );
        self.vault
            .write_file(&self.dir.join("identity.bin"), "identity", &data)
    }

    /// Drops in-memory account changes (e.g. a one-time key consumed by a
    /// pre-key message that then failed verification).
    fn reload_account(&mut self) -> Result<(), String> {
        if let Some(data) = self.vault.read_file(&self.dir.join("identity.bin"), "identity")? {
            let pickle: AccountPickle = serde_json::from_slice(&data).map_err(|e| e.to_string())?;
            self.account = Account::from_pickle(pickle);
        }
        Ok(())
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
                    let json = zeroize::Zeroizing::new(serde_json::to_vec(&s.pickle).unwrap_or_default());
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
        let data = zeroize::Zeroizing::new(serde_json::to_vec(&st.file).map_err(|e| e.to_string())?);
        st.file.sessions.clear();
        self.vault.write_file(&path, &label, &data)
    }

    fn remember(st: &mut ChatState, key: String, value: Incoming) {
        if !st.file.history.contains_key(&key) {
            st.file.history_order.push_back(key.clone());
        }
        st.file.history.insert(key, value);
        while st.file.history_order.len() > MAX_HISTORY_PER_CHAT {
            if let Some(old) = st.file.history_order.pop_front() {
                st.file.history.remove(&old);
                st.file.history_ids.remove(&old);
            }
        }
    }

    fn add_session(st: &mut ChatState, session: Session, peer: PeerIdentity) {
        match st.file.pinned_peer {
            None => st.file.pinned_peer = Some(peer),
            Some(p) if p != peer => {
                // New identity in this chat: reinstall or an attack. Keep
                // the old sessions, block sending until the user decides.
                if !st.file.peer_changed {
                    st.file.previous_peer = Some(p);
                }
                st.file.pinned_peer = Some(peer);
                st.file.verified = false;
                st.file.peer_changed = true;
            }
            _ => {}
        }
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
        let sig = self.account.sign(&ident_signed(&me.curve25519, &peer.curve25519, me.tg_id, peer.tg_id));
        let mut b = Vec::with_capacity(IDENT_LEN);
        b.extend_from_slice(&me.ed25519);
        b.extend_from_slice(&sig.to_bytes());
        b
    }

    fn encrypt_inner(&mut self, chat_id: i64, kind: u8, data: &[u8]) -> Result<String, String> {
        let (idx, needs_ident, peer) = {
            let st = self.chat(chat_id)?;
            if st.file.peer_changed && kind != K_ACCEPT && kind != K_END {
                return Err("Ключ собеседника изменился. Откройте щит и сверьте код безопасности.".into());
            }
            let idx = st.active_index().ok_or("no active secure session in this chat")?;
            let (session, peer) = &st.sessions[idx];
            (idx, !session.has_received_message(), *peer)
        };
        let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(1 + IDENT_LEN + data.len()));
        if needs_ident {
            plain.push(kind | K_IDENT);
            plain.extend_from_slice(&self.ident_block(&peer));
        } else {
            plain.push(kind);
        }
        plain.extend_from_slice(data);
        let st = self.chat(chat_id)?;
        let msg = st.sessions[idx].0.encrypt(&*plain).map_err(|e| e.to_string())?;
        let (t, body) = msg.to_parts();
        let wire_type = if t == 0 { T_PREKEY } else { T_MESSAGE };
        let (text, bytes) = Self::wrap(wire_type, &body);
        let value = match kind {
            K_TEXT => Incoming::Text {
                text: String::from_utf8_lossy(data).into_owned(),
                outgoing: true,
            },
            K_ACCEPT => Incoming::Started { outgoing: true },
            K_FILE if data.len() == 33 => Incoming::File {
                key: data[1..].try_into().unwrap(),
                flags: data[0],
                outgoing: true,
            },
            _ => Incoming::Ended { outgoing: true },
        };
        Self::remember(st, hex32(&bytes), value);
        Ok(text)
    }

    // ---------- public API ----------

    /// Builds an invitation. It carries only public keys, signed together
    /// with this Telegram account id.
    pub fn create_invite(&mut self) -> Result<String, String> {
        if self.my_tg_id == 0 {
            return Err("Telegram account id is not known yet".into());
        }
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
        let sig = self.account.sign(&Self::invite_signed(&id.curve25519, otk.as_bytes(), id.tg_id));
        let mut payload = Vec::with_capacity(INVITE_LEN);
        payload.extend_from_slice(&id.ed25519);
        payload.extend_from_slice(&id.curve25519);
        payload.extend_from_slice(otk.as_bytes());
        payload.extend_from_slice(&id.tg_id.to_be_bytes());
        payload.extend_from_slice(&sig.to_bytes());
        Ok(Self::wrap(T_INVITE, &payload).0)
    }

    fn invite_signed(curve: &[u8; 32], otk: &[u8; 32], tg: i64) -> Vec<u8> {
        let mut v = Vec::with_capacity(INVITE_CTX.len() + 72);
        v.extend_from_slice(INVITE_CTX);
        v.extend_from_slice(curve);
        v.extend_from_slice(otk);
        v.extend_from_slice(&tg.to_be_bytes());
        v
    }

    fn parse_invite(payload: &[u8]) -> Result<(PeerIdentity, Curve25519PublicKey), String> {
        if payload.len() != INVITE_LEN {
            return Err("bad invite".into());
        }
        let ed: [u8; 32] = payload[..32].try_into().unwrap();
        let curve: [u8; 32] = payload[32..64].try_into().unwrap();
        let otk: [u8; 32] = payload[64..96].try_into().unwrap();
        let tg = i64::from_be_bytes(payload[96..104].try_into().unwrap());
        let sig = Ed25519Signature::from_slice(&payload[104..]).map_err(|e| e.to_string())?;
        let ed_key = Ed25519PublicKey::from_slice(&ed).map_err(|e| e.to_string())?;
        ed_key
            .verify(&Self::invite_signed(&curve, &otk, tg), &sig)
            .map_err(|_| "invite signature is invalid".to_string())?;
        Ok((
            PeerIdentity {
                ed25519: ed,
                curve25519: curve,
                tg_id: tg,
            },
            Curve25519PublicKey::from_bytes(otk),
        ))
    }

    /// Accepts an invitation received in `env.chat_id` from `env.sender_id`;
    /// returns the wire text to send back (encrypted ACCEPT).
    pub fn accept_invite(&mut self, env: &Envelope, invite_text: &str) -> Result<String, String> {
        let (t, payload) = Self::unwrap(invite_text).ok_or("not an invitation")?;
        if t != T_INVITE {
            return Err("not an invitation".into());
        }
        let (peer, otk) = Self::parse_invite(&payload)?;
        let me = self.identity();
        if env.outgoing || peer.same_keys(&me) || peer.tg_id == me.tg_id {
            return Err("this is your own invitation".into());
        }
        if peer.tg_id != env.sender_id {
            return Err("the invitation was signed by another Telegram account (forwarded?)".into());
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
            let st = self.chat(env.chat_id)?;
            Self::add_session(st, session, peer);
        }
        let text = self.encrypt_inner(env.chat_id, K_ACCEPT, &[])?;
        self.save_chat(env.chat_id)?;
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

    /// Encrypts an attachment. Returns (document bytes, caption wire text).
    /// Needs an answered session: the first messages of a session carry the
    /// identity block and do not fit into a caption.
    pub fn encrypt_file(
        &mut self,
        chat_id: i64,
        header: &FileHeader,
        content: &[u8],
        flags: u8,
    ) -> Result<(Vec<u8>, String), String> {
        {
            let st = self.chat(chat_id)?;
            let idx = st.active_index().ok_or("no active secure session in this chat")?;
            if !st.sessions[idx].0.has_received_message() {
                return Err("Файлы можно отправлять после первого ответа собеседника в защищённом чате".into());
            }
        }
        let key: [u8; 32] = super::vault::random_bytes();
        let blob = seal_file(&key, header, content)?;
        let mut data = zeroize::Zeroizing::new(Vec::with_capacity(33));
        data.push(flags);
        data.extend_from_slice(&key);
        let caption = self.encrypt_inner(chat_id, K_FILE, &data)?;
        if caption.chars().count() > MAX_CAPTION_CHARS {
            return Err("caption too long".into());
        }
        self.save_chat(chat_id)?;
        Ok((blob, caption))
    }

    /// Builds the END notice. Keys are kept until `forget_sessions` is
    /// called after the notice was actually sent.
    pub fn end_session(&mut self, chat_id: i64) -> Result<String, String> {
        let text = self.encrypt_inner(chat_id, K_END, &[])?;
        self.save_chat(chat_id)?;
        Ok(text)
    }

    pub fn forget_sessions(&mut self, chat_id: i64) -> Result<(), String> {
        let st = self.chat(chat_id)?;
        st.sessions.clear();
        st.file.peer_changed = false;
        st.file.previous_peer = None;
        self.save_chat(chat_id)
    }

    /// Decides what a Telegram text is. Decrypts at most once; later calls
    /// for the same wire bytes are served from the encrypted history.
    pub fn process(&mut self, env: &Envelope, text: &str) -> Incoming {
        let chat_id = env.chat_id;
        let outgoing = env.outgoing;
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
                    let mine = peer.same_keys(&me);
                    // An invite must come from the account that signed it.
                    let sender_ok = if mine || outgoing { peer.tg_id == me.tg_id } else { peer.tg_id == env.sender_id };
                    if !sender_ok {
                        return Incoming::Undecryptable { outgoing };
                    }
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
                // Own ciphertext re-posted as incoming (or the reverse).
                if v.outgoing() != Some(outgoing) {
                    return Incoming::Undecryptable { outgoing };
                }
                if !outgoing && env.message_id != 0 {
                    match st.file.history_ids.get(&key) {
                        Some(id) if *id != env.message_id => {
                            return Incoming::Undecryptable { outgoing };
                        }
                        Some(_) => {}
                        None => {
                            st.file.history_ids.insert(key.clone(), env.message_id);
                        }
                    }
                }
                return v.clone();
            }
        }
        if outgoing {
            // Our own ciphertext is encrypted for the peer, not for us.
            return Incoming::Undecryptable { outgoing: true };
        }
        let result = match t {
            T_PREKEY => self.decrypt_prekey(env, &payload),
            T_MESSAGE => self.decrypt_normal(env, &payload),
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
            if env.message_id != 0 {
                st.file.history_ids.insert(key.clone(), env.message_id);
            }
            Self::remember(st, key, value.clone());
        }
        if let Err(e) = self.save_chat(chat_id) {
            log::error!("Unable to save ZK chat state: {}", e);
        }
        value
    }

    fn decrypt_prekey(&mut self, env: &Envelope, body: &[u8]) -> Result<Incoming, String> {
        let chat_id = env.chat_id;
        let pre = PreKeyMessage::from_bytes(body).map_err(|e| e.to_string())?;
        let msg = OlmMessage::PreKey(pre.clone());
        // A peer keeps sending pre-key messages until we answer: reuse the
        // matching session first.
        {
            let st = self.chat(chat_id)?;
            let sid = pre.session_id();
            if let Some(i) = st.sessions.iter().position(|(s, _)| s.session_id() == sid) {
                let peer = st.sessions[i].1;
                if peer.tg_id != env.sender_id {
                    return Err("pre-key message from another Telegram account".into());
                }
                let plain = zeroize::Zeroizing::new(st.sessions[i].0.decrypt(&msg).map_err(|e| e.to_string())?);
                let s = st.sessions.remove(i);
                st.sessions.push(s);
                return Self::handle_plain(st, peer, &plain, false);
            }
        }
        let their_curve = pre.identity_key();
        let res = self
            .account
            .create_inbound_session(session_config(), their_curve, &pre)
            .map_err(|e| e.to_string())?;
        let plain = zeroize::Zeroizing::new(res.plaintext);
        let me = self.identity();
        let check = (|| -> Result<PeerIdentity, String> {
            let p = &plain;
            if env.sender_id == 0 || env.sender_id == me.tg_id {
                return Err("pre-key message has no valid sender".into());
            }
            if p.is_empty() || p[0] & K_IDENT == 0 || p.len() < 1 + IDENT_LEN {
                return Err("first message of a session carries no identity".into());
            }
            let ed: [u8; 32] = p[1..33].try_into().unwrap();
            let sig = Ed25519Signature::from_slice(&p[33..1 + IDENT_LEN]).map_err(|e| e.to_string())?;
            let ed_key = Ed25519PublicKey::from_slice(&ed).map_err(|e| e.to_string())?;
            ed_key
                .verify(
                    &ident_signed(their_curve.as_bytes(), &me.curve25519, env.sender_id, me.tg_id),
                    &sig,
                )
                .map_err(|_| "identity signature is invalid (wrong sender or forwarded)".to_string())?;
            Ok(PeerIdentity {
                ed25519: ed,
                curve25519: their_curve.to_bytes(),
                tg_id: env.sender_id,
            })
        })();
        let peer = match check {
            Ok(p) => p,
            Err(e) => {
                // vodozemac already removed the one-time key in memory.
                self.reload_account()?;
                return Err(e);
            }
        };
        let st = self.chat(chat_id)?;
        Self::add_session(st, res.session, peer);
        let value = Self::handle_plain(st, peer, &plain, false)?;
        // Session first, then the account without the used one-time key:
        // a crash in between leaves a usable session, never a lost one.
        self.save_chat(chat_id)?;
        self.save_account()?;
        Ok(value)
    }

    fn decrypt_normal(&mut self, env: &Envelope, body: &[u8]) -> Result<Incoming, String> {
        let msg = OlmMessage::from_parts(1, body).map_err(|e| e.to_string())?;
        let st = self.chat(env.chat_id)?;
        let mut last_err = String::from("no session");
        for i in (0..st.sessions.len()).rev() {
            let peer = st.sessions[i].1;
            if peer.tg_id != env.sender_id {
                continue;
            }
            match st.sessions[i].0.decrypt(&msg) {
                Ok(plain) => {
                    let plain = zeroize::Zeroizing::new(plain);
                    let s = st.sessions.remove(i);
                    st.sessions.push(s);
                    return Self::handle_plain(st, peer, &plain, false);
                }
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
            K_FILE => {
                if body.len() != 33 {
                    return Err("bad file key".into());
                }
                Ok(Incoming::File {
                    key: body[1..].try_into().unwrap(),
                    flags: body[0],
                    outgoing,
                })
            }
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
        let active = st.active_index().map(|i| st.sessions[i].1);
        Ok(ChatStatus {
            state: if active.is_some() { "active" } else { "none" }.into(),
            safety_number: active.map(|p| safety_number(&me, &p)),
            verified: st.file.verified,
            peer_changed: st.file.peer_changed,
            has_history: st
                .file
                .history
                .values()
                .any(|v| matches!(v, Incoming::Text { .. } | Incoming::File { .. })),
        })
    }

    /// Marks the current identity as verified (codes compared). Also
    /// accepts a changed identity.
    pub fn set_verified(&mut self, chat_id: i64, verified: bool) -> Result<(), String> {
        let st = self.chat(chat_id)?;
        if st.active_index().is_none() {
            return Err("no active secure session".into());
        }
        if verified {
            Self::accept_pinned(st);
        }
        st.file.verified = verified;
        self.save_chat(chat_id)
    }

    fn accept_pinned(st: &mut ChatState) {
        if let Some(p) = st.file.pinned_peer {
            st.sessions.retain(|(_, q)| *q == p);
        }
        st.file.peer_changed = false;
        st.file.previous_peer = None;
    }

    /// The user trusts the new identity without comparing codes.
    pub fn accept_new_peer(&mut self, chat_id: i64) -> Result<(), String> {
        let st = self.chat(chat_id)?;
        Self::accept_pinned(st);
        st.file.verified = false;
        self.save_chat(chat_id)
    }

    /// The user rejects the new identity: its sessions are dropped and the
    /// previous identity becomes active again.
    pub fn reject_new_peer(&mut self, chat_id: i64) -> Result<(), String> {
        let st = self.chat(chat_id)?;
        if !st.file.peer_changed {
            return Ok(());
        }
        if let Some(bad) = st.file.pinned_peer {
            st.sessions.retain(|(_, q)| *q != bad);
        }
        st.file.pinned_peer = st.file.previous_peer.take();
        st.file.peer_changed = false;
        self.save_chat(chat_id)
    }

    /// Changes the passphrase in one step (tests, tools).
    #[cfg(test)]
    pub fn rekey(&mut self, new_passphrase: &str) -> Result<(), String> {
        self.prepare_rekey(new_passphrase)?;
        self.commit_rekey()
    }

    /// Two-phase passphrase change, so the PGP key can be switched in
    /// between: until `commit_rekey`, both passphrases open the store.
    pub fn prepare_rekey(&self, new_passphrase: &str) -> Result<(), String> {
        self.vault.prepare_rewrap(&self.dir.join("key.bin"), new_passphrase)
    }

    pub fn commit_rekey(&self) -> Result<(), String> {
        Vault::commit_rewrap(&self.dir.join("key.bin"))
    }

    pub fn abort_rekey(&self) {
        Vault::abort_rewrap(&self.dir.join("key.bin"))
    }

    /// Drops decrypted history of a chat from memory (kept on disk).
    pub fn unload_chat(&mut self, chat_id: i64) {
        if let Some(mut st) = self.chats.remove(&chat_id) {
            use zeroize::Zeroize;
            for v in st.file.history.values_mut() {
                if let Incoming::Text { text, .. } = v {
                    text.zeroize();
                }
            }
        }
    }
}

/// Metadata stored inside the encrypted attachment, never in Telegram.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHeader {
    pub name: String,
    pub mime: String,
    pub caption: Option<String>,
}

pub fn seal_file(key: &[u8; 32], header: &FileHeader, content: &[u8]) -> Result<Vec<u8>, String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    let h = serde_json::to_vec(header).map_err(|e| e.to_string())?;
    let mut plain = zeroize::Zeroizing::new(Vec::with_capacity(4 + h.len() + content.len()));
    plain.extend_from_slice(&(h.len() as u32).to_be_bytes());
    plain.extend_from_slice(&h);
    plain.extend_from_slice(content);
    let nonce: [u8; 24] = super::vault::random_bytes();
    let ct = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: FILE_AAD })
        .map_err(|_| "encryption failed".to_string())?;
    let mut out = Vec::with_capacity(FILE_MAGIC.len() + 24 + ct.len());
    out.extend_from_slice(FILE_MAGIC);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn open_file(key: &[u8; 32], blob: &[u8]) -> Result<(FileHeader, zeroize::Zeroizing<Vec<u8>>), String> {
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::{XChaCha20Poly1305, XNonce};
    let n = FILE_MAGIC.len();
    if blob.len() < n + 24 || &blob[..n] != FILE_MAGIC {
        return Err("not an encrypted attachment".into());
    }
    let plain = zeroize::Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(XNonce::from_slice(&blob[n..n + 24]), Payload { msg: &blob[n + 24..], aad: FILE_AAD })
            .map_err(|_| "attachment is damaged or the key is wrong".to_string())?,
    );
    if plain.len() < 4 {
        return Err("bad attachment".into());
    }
    let hl = u32::from_be_bytes(plain[..4].try_into().unwrap()) as usize;
    if plain.len() < 4 + hl {
        return Err("bad attachment".into());
    }
    let header: FileHeader = serde_json::from_slice(&plain[4..4 + hl]).map_err(|e| e.to_string())?;
    Ok((header, zeroize::Zeroizing::new(plain[4 + hl..].to_vec())))
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

    const A: i64 = 100;
    const B: i64 = 200;

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

    fn env(sender: i64, me: i64) -> Envelope {
        Envelope { chat_id: 1, message_id: 0, sender_id: sender, outgoing: sender == me }
    }
    // a's view of a message sent by `sender`
    fn on_a(sender: i64) -> Envelope { env(sender, A) }
    fn on_b(sender: i64) -> Envelope { env(sender, B) }

    fn pair() -> (ZkEngine, ZkEngine, PathBuf, PathBuf) {
        let (da, db) = (tmp("a"), tmp("b"));
        let a = ZkEngine::open(&da, "alice-pass", A).unwrap();
        let b = ZkEngine::open(&db, "bob-pass", B).unwrap();
        (a, b, da, db)
    }

    fn handshake_with(a: &mut ZkEngine, b: &mut ZkEngine, b_id: i64) {
        let invite = a.create_invite().unwrap();
        let eb = env(A, b_id);
        assert_eq!(b.process(&eb, &invite), Incoming::Invite { outgoing: false, accepted: false });
        assert_eq!(a.process(&on_a(A), &invite), Incoming::Invite { outgoing: true, accepted: false });
        let accept = b.accept_invite(&eb, &invite).unwrap();
        assert_eq!(b.process(&eb, &invite), Incoming::Invite { outgoing: false, accepted: true });
        assert_eq!(a.process(&on_a(b_id), &accept), Incoming::Started { outgoing: false });
        assert_eq!(b.process(&env(b_id, b_id), &accept), Incoming::Started { outgoing: true });
    }

    fn handshake(a: &mut ZkEngine, b: &mut ZkEngine) {
        handshake_with(a, b, B)
    }

    fn text(t: &str, outgoing: bool) -> Incoming {
        Incoming::Text { text: t.into(), outgoing }
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

        let m1 = b.encrypt_text(1, "привет").unwrap();
        let m2 = b.encrypt_text(1, "второе").unwrap();
        assert!(m1[0].split(' ').all(|w| wordcoder::decode(w).is_some()));
        assert_eq!(a.process(&on_a(B), &m2[0]), text("второе", false));
        assert_eq!(a.process(&on_a(B), &m1[0]), text("привет", false));
        let r = a.encrypt_text(1, "hi bob").unwrap();
        assert_eq!(b.process(&on_b(A), &r[0]), text("hi bob", false));
        for i in 0..5 {
            let x = a.encrypt_text(1, &format!("a{}", i)).unwrap();
            let y = b.encrypt_text(1, &format!("b{}", i)).unwrap();
            assert_eq!(b.process(&on_b(A), &x[0]), text(&format!("a{}", i), false));
            assert_eq!(a.process(&on_a(B), &y[0]), text(&format!("b{}", i), false));
        }
        assert_eq!(a.process(&on_a(B), &m1[0]), text("привет", false));
        assert_eq!(b.process(&on_b(B), &m1[0]), text("привет", true));
        assert!(a.status(1).unwrap().has_history);
        assert_eq!(a.process(&on_a(B), "обычное сообщение"), Incoming::NotZk);
    }

    #[test]
    fn state_survives_restart_and_wrong_passphrase_fails() {
        let (mut a, mut b, da, db) = pair();
        handshake(&mut a, &mut b);
        let m = b.encrypt_text(1, "до перезапуска").unwrap();
        assert!(matches!(a.process(&on_a(B), &m[0]), Incoming::Text { .. }));
        drop(a);
        drop(b);
        assert!(ZkEngine::open(&da, "wrong", A).is_err());
        let mut a = ZkEngine::open(&da, "alice-pass", A).unwrap();
        let mut b = ZkEngine::open(&db, "bob-pass", B).unwrap();
        assert_eq!(a.process(&on_a(B), &m[0]), text("до перезапуска", false));
        let r = a.encrypt_text(1, "после").unwrap();
        assert_eq!(b.process(&on_b(A), &r[0]), text("после", false));
    }

    #[test]
    fn missing_key_file_is_not_silently_recreated() {
        let d = tmp("k");
        drop(ZkEngine::open(&d, "p", A).unwrap());
        fs::remove_file(d.join("key.bin")).unwrap();
        assert!(ZkEngine::open(&d, "p", A).is_err());
    }

    #[test]
    fn files_on_disk_contain_no_plaintext() {
        let (mut a, mut b, da, _) = pair();
        handshake(&mut a, &mut b);
        let m = b.encrypt_text(1, "SUPERSECRETWORD").unwrap();
        a.process(&on_a(B), &m[0]);
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
        assert_eq!(a.process(&on_a(B), &bad), Incoming::Undecryptable { outgoing: false });
        let mut eve = ZkEngine::open(&tmp("e"), "eve", 300).unwrap();
        assert_eq!(eve.process(&env(B, 300), &m[0]), Incoming::Undecryptable { outgoing: false });
        let inv = a.create_invite().unwrap();
        let mut ib = wordcoder::decode(&inv).unwrap();
        ib[10] ^= 1;
        assert!(b.accept_invite(&on_b(A), &wordcoder::encode(&ib)).is_err());
    }

    #[test]
    fn forwarded_invite_and_relayed_accept_are_rejected() {
        // Mallory (300) forwards Alice's invite to Bob as if it were his.
        let (mut a, mut b, _, _) = pair();
        let invite = a.create_invite().unwrap();
        let from_mallory = env(300, B);
        assert_eq!(b.process(&from_mallory, &invite), Incoming::Undecryptable { outgoing: false });
        assert!(b.accept_invite(&from_mallory, &invite).is_err());
        // Bob accepts the genuine invite; Mallory relays Bob's ACCEPT to Alice.
        let accept = b.accept_invite(&on_b(A), &invite).unwrap();
        assert_eq!(a.process(&on_a(300), &accept), Incoming::Undecryptable { outgoing: false });
        // the one-time key was not burned: the genuine ACCEPT still works
        assert_eq!(a.process(&on_a(B), &accept), Incoming::Started { outgoing: false });
        // and messages relayed by Mallory are ignored
        let m = b.encrypt_text(1, "secret").unwrap();
        assert_eq!(a.process(&on_a(300), &m[0]), Incoming::Undecryptable { outgoing: false });
        assert_eq!(a.process(&on_a(B), &m[0]), text("secret", false));
    }

    #[test]
    fn replays_and_spoofed_direction_are_rejected() {
        let (mut a, mut b, _, _) = pair();
        handshake(&mut a, &mut b);
        let m = b.encrypt_text(1, "да").unwrap();
        let e1 = Envelope { chat_id: 1, message_id: 10, sender_id: B, outgoing: false };
        assert_eq!(a.process(&e1, &m[0]), text("да", false));
        assert_eq!(a.process(&e1, &m[0]), text("да", false)); // reload of the same message
        let e2 = Envelope { message_id: 11, ..e1 };
        assert_eq!(a.process(&e2, &m[0]), Incoming::Undecryptable { outgoing: false });
        // Alice's own ciphertext re-posted as if Bob sent it
        let mine = a.encrypt_text(1, "моё").unwrap();
        assert_eq!(a.process(&on_a(B), &mine[0]), Incoming::Undecryptable { outgoing: false });
    }

    #[test]
    fn key_change_blocks_sending_until_user_decides() {
        let (mut a, mut b, _, _) = pair();
        handshake(&mut a, &mut b);
        a.set_verified(1, true).unwrap();
        let sn_old = a.status(1).unwrap().safety_number;
        // Bob "reinstalls": new identity in the same chat
        let mut b2 = ZkEngine::open(&tmp("b2"), "bob2", B).unwrap();
        handshake(&mut a, &mut b2);
        let st = a.status(1).unwrap();
        assert!(st.peer_changed);
        assert!(!st.verified);
        assert_ne!(st.safety_number, sn_old);
        assert!(a.encrypt_text(1, "x").is_err(), "sending must be blocked");
        // reject: back to old Bob, who still works
        a.reject_new_peer(1).unwrap();
        assert_eq!(a.status(1).unwrap().safety_number, sn_old);
        let t = a.encrypt_text(1, "old bob").unwrap();
        assert_eq!(b.process(&on_b(A), &t[0]), text("old bob", false));
        // new identity again, this time accepted after comparing codes
        let mut b3 = ZkEngine::open(&tmp("b3"), "bob3", B).unwrap();
        handshake(&mut a, &mut b3);
        assert!(a.encrypt_text(1, "x").is_err());
        a.set_verified(1, true).unwrap();
        let t = a.encrypt_text(1, "new bob").unwrap();
        assert_eq!(b3.process(&on_b(A), &t[0]), text("new bob", false));
        // end session: keys kept until forget_sessions
        let end = a.end_session(1).unwrap();
        assert_eq!(a.status(1).unwrap().state, "active");
        a.forget_sessions(1).unwrap();
        assert_eq!(b3.process(&on_b(A), &end), Incoming::Ended { outgoing: false });
        assert_eq!(a.status(1).unwrap().state, "none");
        assert_eq!(b3.status(1).unwrap().state, "none");
        assert!(a.encrypt_text(1, "x").is_err());
    }

    #[test]
    fn long_text_is_chunked_within_telegram_limit() {
        let (mut a, mut b, _, _) = pair();
        handshake(&mut a, &mut b);
        let long: String = "щ".repeat(1500);
        let parts = b.encrypt_text(1, &long).unwrap();
        assert!(parts.len() >= 8);
        let mut joined = String::new();
        for p in &parts {
            assert!(p.chars().count() <= 4096, "{} chars", p.chars().count());
            assert!(wordcoder::decode(p).unwrap().len() <= MAX_WIRE_BYTES);
            if let Incoming::Text { text, .. } = a.process(&on_a(B), p) {
                joined.push_str(&text);
            }
        }
        assert_eq!(joined, long);
    }

    #[test]
    fn text_arriving_before_accept_still_opens_session() {
        let (mut a, mut b, _, _) = pair();
        let invite = a.create_invite().unwrap();
        let accept = b.accept_invite(&on_b(A), &invite).unwrap();
        let t = b.encrypt_text(1, "first").unwrap();
        assert_eq!(a.process(&on_a(B), &t[0]), text("first", false));
        assert_eq!(a.process(&on_a(B), &accept), Incoming::Started { outgoing: false });
        assert_eq!(a.status(1).unwrap().state, "active");
    }

    #[test]
    fn files_roundtrip_and_fit_caption() {
        let (mut a, mut b, _, _) = pair();
        handshake(&mut a, &mut b);
        let h = FileHeader { name: "фото.jpg".into(), mime: "image/jpeg".into(), caption: Some("подпись".into()) };
        assert!(b.encrypt_file(1, &h, b"x", 0).is_err());
        let t = a.encrypt_text(1, "ping").unwrap();
        b.process(&on_b(A), &t[0]);
        let content = vec![7u8; 100_000];
        for i in 0..20 {
            let (blob, caption) = b.encrypt_file(1, &h, &content, FILE_FLAG_VOICE).unwrap();
            assert!(caption.chars().count() <= MAX_CAPTION_CHARS, "{}", caption.chars().count());
            assert!(!blob.windows(8).any(|w| w == "фото".as_bytes()));
            let Incoming::File { key, flags, outgoing } = a.process(&on_a(B), &caption) else {
                panic!("expected file at {}", i)
            };
            assert_eq!((flags, outgoing), (FILE_FLAG_VOICE, false));
            let (hh, data) = open_file(&key, &blob).unwrap();
            assert_eq!(hh, h);
            assert_eq!(&data[..], &content[..]);
            assert!(matches!(b.process(&on_b(B), &caption), Incoming::File { outgoing: true, .. }));
            let mut bad = blob.clone();
            let l = bad.len();
            bad[l - 1] ^= 1;
            assert!(open_file(&key, &bad).is_err());
        }
    }

    #[test]
    fn rekey_keeps_data() {
        let (mut a, mut b, da, _) = pair();
        handshake(&mut a, &mut b);
        let m = b.encrypt_text(1, "keep").unwrap();
        a.process(&on_a(B), &m[0]);
        a.rekey("new-pass").unwrap();
        drop(a);
        assert!(ZkEngine::open(&da, "alice-pass", A).is_err());
        let mut a = ZkEngine::open(&da, "new-pass", A).unwrap();
        assert_eq!(a.process(&on_a(B), &m[0]), text("keep", false));
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
