//! Glue between the pure ZK engine (`crypto::zk`) and the app: owns the
//! unlocked engine, opened with the local passphrase, dropped on lock.

use crate::crypto::zk::engine::{Incoming, ZkEngine};
use crate::model::{MessageContent, MessageZk};
use crate::{state, store};
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::Manager;

#[derive(Default)]
pub struct ZkState(pub Mutex<Option<ZkEngine>>);

fn zk_dir<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> PathBuf {
    PathBuf::from(store::get_application_folder(app)).join("zk")
}

/// Opens the engine with the given passphrase (called after the passphrase
/// was checked against the PGP key).
pub fn unlock<R: tauri::Runtime>(app: &tauri::AppHandle<R>, passphrase: &str) -> Result<(), String> {
    let engine = ZkEngine::open(&zk_dir(app), passphrase)?;
    let st = app.state::<ZkState>();
    *st.0.lock().unwrap() = Some(engine);
    Ok(())
}

pub fn lock<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let st = app.state::<ZkState>();
    *st.0.lock().unwrap() = None;
}

pub fn with_engine<R: tauri::Runtime, T>(
    app: &tauri::AppHandle<R>,
    f: impl FnOnce(&mut ZkEngine) -> Result<T, String>,
) -> Result<T, String> {
    let st = app.state::<ZkState>();
    let mut guard = st.0.lock().unwrap();
    match guard.as_mut() {
        Some(engine) => f(engine),
        None => Err("app is locked".into()),
    }
}

fn zk(kind: &str, text: Option<String>, outgoing: bool) -> MessageContent {
    MessageContent::Zk(MessageZk {
        kind: kind.into(),
        text,
        outgoing,
    })
}

/// Called by the parser for every text message. Returns `None` for normal
/// (non ZK) text.
pub fn parse_text<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    chat_id: i64,
    text: &str,
    outgoing: bool,
) -> Option<MessageContent> {
    if !ZkEngine::looks_like_zk(text) {
        return None;
    }
    let result = with_engine(app, |e| Ok(e.process(chat_id, text, outgoing)));
    let incoming = match result {
        Ok(v) => v,
        Err(_) => return Some(zk("locked", None, outgoing)),
    };
    Some(match incoming {
        Incoming::NotZk => return None,
        Incoming::Invite { outgoing, accepted } => {
            zk(if accepted { "invite_accepted" } else { "invite" }, None, outgoing)
        }
        Incoming::Started { outgoing } => zk("started", None, outgoing),
        Incoming::Ended { outgoing } => zk("ended", None, outgoing),
        Incoming::Undecryptable { outgoing } => zk("undecryptable", None, outgoing),
        Incoming::Text { text, outgoing } => {
            // Decrypted once into the encrypted history either way, shown
            // only in secret view.
            if state::is_chat_revealed(app, chat_id) {
                zk("text", Some(text), outgoing)
            } else {
                zk("hidden", None, outgoing)
            }
        }
    })
}
