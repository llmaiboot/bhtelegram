//! Glue between the pure ZK engine (`crypto::zk`) and the app: owns the
//! unlocked engine, opened with the local passphrase, dropped on lock.

use crate::crypto::zk::engine::{Envelope, Incoming, ZkEngine, FILE_FLAG_VOICE};
use crate::model::{MessageContent, MessageZk};
use crate::{state, store};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use tauri::Manager;

#[derive(Default)]
pub struct ZkState {
    engine: Mutex<Option<ZkEngine>>,
    /// Serializes unlock attempts (first-use key creation is not racy).
    unlock: Mutex<()>,
    /// Bumped on every lock: work started before a lock must not install
    /// an unlocked engine or return decrypted text after it.
    epoch: AtomicU64,
}

fn guard<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic inside the engine must not make the app unlockable/unlockable.
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn zk_dir<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> PathBuf {
    PathBuf::from(store::get_application_folder(app)).join("zk")
}

pub fn epoch<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> u64 {
    app.state::<ZkState>().epoch.load(Ordering::SeqCst)
}

/// Opens the engine with the given passphrase (after the passphrase was
/// checked against the PGP key). `epoch` is the value read before the
/// (slow) checks started; a lock in between cancels the unlock.
pub fn unlock<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    passphrase: &str,
    epoch_at_start: u64,
) -> Result<(), String> {
    let st = app.state::<ZkState>();
    let _u = guard(&st.unlock);
    let my_id = state::get_my_id(app).unwrap_or(0);
    let engine = ZkEngine::open(&zk_dir(app), passphrase, my_id)?;
    let mut g = guard(&st.engine);
    if st.epoch.load(Ordering::SeqCst) != epoch_at_start {
        return Err("app was locked".into());
    }
    *g = Some(engine);
    Ok(())
}

pub fn lock<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let st = app.state::<ZkState>();
    st.epoch.fetch_add(1, Ordering::SeqCst);
    *guard(&st.engine) = None;
}

pub fn set_my_id<R: tauri::Runtime>(app: &tauri::AppHandle<R>, id: i64) {
    let st = app.state::<ZkState>();
    let mut g = guard(&st.engine);
    if let Some(e) = g.as_mut() {
        e.set_my_tg_id(id);
    }
}

pub fn with_engine<R: tauri::Runtime, T>(
    app: &tauri::AppHandle<R>,
    f: impl FnOnce(&mut ZkEngine) -> Result<T, String>,
) -> Result<T, String> {
    let st = app.state::<ZkState>();
    let mut g = guard(&st.engine);
    match g.as_mut() {
        Some(engine) => f(engine),
        None => Err("app is locked".into()),
    }
}

/// Plain (non ZK) sending into a chat must be refused when a secure
/// session is active there, or when the app is locked and the chat may
/// have one: a stale UI must never downgrade a secure chat to plaintext.
pub fn guard_plain_send<R: tauri::Runtime>(app: &tauri::AppHandle<R>, chat_id: i64) -> Result<(), String> {
    match with_engine(app, |e| e.status(chat_id)) {
        Ok(s) if s.state == "active" => {
            Err("В этом чате идёт защищённый сеанс: обычная отправка запрещена".into())
        }
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

/// ZK content is shown only in explicit secret view, never through the PGP
/// "auto decrypt" setting.
pub fn is_revealed<R: tauri::Runtime>(app: &tauri::AppHandle<R>, chat_id: i64) -> bool {
    state::is_chat_explicitly_revealed(app, chat_id)
}

pub fn envelope(message: &tdlib::types::Message) -> Envelope {
    let sender_id = match &message.sender_id {
        tdlib::enums::MessageSender::User(u) => u.user_id,
        tdlib::enums::MessageSender::Chat(_) => 0,
    };
    Envelope {
        chat_id: message.chat_id,
        message_id: message.id,
        sender_id,
        outgoing: message.is_outgoing,
    }
}

fn zk(kind: &str, text: Option<String>, outgoing: bool) -> MessageContent {
    MessageContent::Zk(MessageZk {
        kind: kind.into(),
        text,
        outgoing,
        file: None,
        is_file: false,
        voice: false,
    })
}

/// Encrypted attachment: a document whose caption is ZK wire text.
pub fn parse_document<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    env: &Envelope,
    caption: &str,
    document: &tdlib::types::File,
) -> Option<MessageContent> {
    if !ZkEngine::looks_like_zk(caption) {
        return None;
    }
    let mut content = parse_text(app, env, caption)?;
    if let MessageContent::Zk(z) = &mut content {
        z.is_file = true;
        // A text in a caption is not expected. "hidden" here can only be a
        // hidden file (texts never travel as captions), so keep it.
        if z.kind == "text" {
            z.kind = "undecryptable".into();
            z.text = None;
        }
        if z.kind == "file" {
            z.file = Some(crate::model::File::from(document));
        }
    }
    Some(content)
}

pub fn file_key<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    env: &Envelope,
    caption: &str,
) -> Result<[u8; 32], String> {
    match with_engine(app, |e| Ok(e.process(env, caption)))? {
        Incoming::File { key, .. } => Ok(key),
        _ => Err("not an encrypted attachment".into()),
    }
}

/// Called by the parser for every text message. Returns `None` for normal
/// (non ZK) text.
pub fn parse_text<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    env: &Envelope,
    text: &str,
) -> Option<MessageContent> {
    if !ZkEngine::looks_like_zk(text) {
        return None;
    }
    let outgoing = env.outgoing;
    let start = epoch(app);
    let incoming = match with_engine(app, |e| Ok(e.process(env, text))) {
        Ok(v) => v,
        Err(_) => return Some(zk("locked", None, outgoing)),
    };
    // Revealed check after decryption, and only if no lock happened.
    let revealed = is_revealed(app, env.chat_id) && epoch(app) == start;
    Some(match incoming {
        Incoming::NotZk => return None,
        Incoming::Invite { outgoing, accepted } => {
            zk(if accepted { "invite_accepted" } else { "invite" }, None, outgoing)
        }
        Incoming::Started { outgoing } => {
            crate::emit(app, "update-zk-status", env.chat_id);
            zk("started", None, outgoing)
        }
        Incoming::Ended { outgoing } => {
            crate::emit(app, "update-zk-status", env.chat_id);
            zk("ended", None, outgoing)
        }
        Incoming::Undecryptable { outgoing } => zk("undecryptable", None, outgoing),
        Incoming::File { flags, outgoing, .. } => {
            let mut c = zk(if revealed { "file" } else { "hidden" }, None, outgoing);
            if let MessageContent::Zk(z) = &mut c {
                z.is_file = true;
                z.voice = flags & FILE_FLAG_VOICE != 0;
            }
            c
        }
        Incoming::Text { text, outgoing } => {
            if revealed {
                zk("text", Some(text), outgoing)
            } else {
                zk("hidden", None, outgoing)
            }
        }
    })
}
