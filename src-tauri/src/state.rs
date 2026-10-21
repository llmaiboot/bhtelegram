use pgp::{composed::SignedSecretKey, packet::PublicSubkey};
use std::{
    collections::{HashMap, HashSet},
    error::Error,
    sync::Mutex,
};
use tauri::Manager;

use crate::crypto;

#[derive(Default)]
pub struct AppState {
    my_id: Option<i64>,
    my_key: Option<SignedSecretKey>,
    keys_cache: HashMap<i64, PublicSubkey>,
    pgp_passphrase: String,
    client_id: i32,
    logged_in: bool,
    close_requested: bool,
    /// Chats whose PGP content the user explicitly revealed in this session
    /// (see `is_chat_revealed`). Never persisted.
    revealed_chats: HashSet<i64>,
}

impl AppState {
    pub fn new() -> Self {
        AppState {
            my_id: None,
            my_key: None,
            keys_cache: HashMap::new(),
            pgp_passphrase: "".into(),
            client_id: 0,
            logged_in: false,
            close_requested: false,
            revealed_chats: HashSet::new(),
        }
    }
}

pub fn set_pgp_passphrase<R: tauri::Runtime>(app: &tauri::AppHandle<R>, pgp_passphrase: &str) {
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap();
    use zeroize::Zeroize;
    state.pgp_passphrase.zeroize();
    state.pgp_passphrase = String::from(pgp_passphrase);
}

pub fn get_pgp_passphrase<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> String {
    let state = app.state::<Mutex<AppState>>();
    let state = state.lock().unwrap();
    state.pgp_passphrase.clone()
}

pub fn set_client_id<R: tauri::Runtime>(app: &tauri::AppHandle<R>, client_id: i32) {
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap();
    state.client_id = client_id;
}

pub fn get_client_id<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> i32 {
    let state = app.state::<Mutex<AppState>>();
    let state = state.lock().unwrap();
    state.client_id
}

pub fn request_close<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    log::trace!("Set closing state");
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap();
    state.close_requested = true;
}

pub fn close_requested<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> bool {
    let state = app.state::<Mutex<AppState>>();
    let state = state.lock().unwrap();
    state.close_requested
}

pub fn is_logged_in<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> bool {
    let state = app.state::<Mutex<AppState>>();
    let state = state.lock().unwrap();
    state.logged_in
}

pub fn set_logged_in<R: tauri::Runtime>(app: &tauri::AppHandle<R>, logged_in: bool) {
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap();
    state.logged_in = logged_in;
}

pub fn set_my_id<R: tauri::Runtime>(app: &tauri::AppHandle<R>, my_id: i64) {
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap();
    state.my_id = Some(my_id);
}

pub fn get_my_id<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> Option<i64> {
    let state = app.state::<Mutex<AppState>>();
    let state = state.lock().unwrap();
    state.my_id
}

pub fn get_my_key<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<SignedSecretKey, Box<dyn Error>> {
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap();
    match &state.my_key {
        Some(key) => {
            return Ok(key.clone());
        }
        None => match crypto::pgp::load_my_key(&app) {
            Ok(key) => {
                state.my_key = Some(key.clone());
                return Ok(key);
            }
            Err(err) => {
                return Err(err);
            }
        },
    }
}

pub fn get_my_encryption_key<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<PublicSubkey, Box<dyn Error>> {
    let key = get_my_key(app)?;
    Ok(crypto::pgp::get_encryption_key_from_secret_key(&key)?)
}

pub fn get_chat_encryption_key<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    chat_id: i64,
) -> Result<PublicSubkey, Box<dyn Error>> {
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap();
    let keys = &mut state.keys_cache;
    match keys.get(&chat_id) {
        Some(key) => {
            return Ok(key.clone());
        }
        None => {
            let key_path = crypto::pgp::get_chat_key_path(app, chat_id)?;
            let public_key = crypto::pgp::load_public_key_from_file(&key_path)?;
            let encryption_key = crypto::pgp::get_encryption_key_from_public_key(&public_key)?;
            keys.insert(chat_id, encryption_key.clone());
            return Ok(encryption_key);
        }
    }
}

/// Drops the cached encryption key of a chat, so that a replaced or removed
/// peer key is never used again for new messages.
pub fn invalidate_chat_encryption_key<R: tauri::Runtime>(app: &tauri::AppHandle<R>, chat_id: i64) {
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap();
    state.keys_cache.remove(&chat_id);
}

/// PGP content of a chat is decrypted only when it has been revealed
/// explicitly, unless the user enabled automatic decryption.
pub fn is_chat_revealed<R: tauri::Runtime>(app: &tauri::AppHandle<R>, chat_id: i64) -> bool {
    if crate::store::get_auto_decrypt(app) {
        return true;
    }
    let state = app.state::<Mutex<AppState>>();
    let state = state.lock().unwrap();
    state.revealed_chats.contains(&chat_id)
}

/// Revealed by the user in this session, ignoring the auto-decrypt option.
pub fn is_chat_explicitly_revealed<R: tauri::Runtime>(app: &tauri::AppHandle<R>, chat_id: i64) -> bool {
    let state = app.state::<Mutex<AppState>>();
    let state = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    state.revealed_chats.contains(&chat_id)
}

pub fn forget_cached_key<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let state = app.state::<Mutex<AppState>>();
    state.lock().unwrap_or_else(std::sync::PoisonError::into_inner).my_key = None;
}

/// Forgets the cached (decrypted) PGP key and the passphrase.
pub fn forget_secrets<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    use zeroize::Zeroize;
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    state.pgp_passphrase.zeroize();
    state.my_key = None;
    state.keys_cache.clear();
    state.revealed_chats.clear();
}

pub fn set_chat_revealed<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    chat_id: i64,
    revealed: bool,
) {
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap();
    if revealed {
        state.revealed_chats.insert(chat_id);
    } else {
        state.revealed_chats.remove(&chat_id);
    }
}

pub fn hide_all_chats<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let state = app.state::<Mutex<AppState>>();
    let mut state = state.lock().unwrap();
    state.revealed_chats.clear();
}
