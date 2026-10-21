use crate::{crypto, settings, state, store, telegram::client::Client};
use pgp::types::KeyDetails;
use std::thread;

#[tauri::command]
pub fn get_default_folder<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> String {
    settings::get_default_folder(&app)
}

#[tauri::command]
pub fn generate_pgp_key<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    passphrase: &str,
) -> Result<String, String> {
    let key = crypto::pgp::generate_key(passphrase).map_err(|e| e.to_string())?;
    let armored_key = crypto::pgp::get_armored_private_key(&key).map_err(|e| e.to_string())?;
    store::set_secret_key(&app, &armored_key);
    Ok(key.fingerprint().to_string())
}

#[tauri::command]
pub fn import_pgp_key<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    key_path: &str,
    passphrase: &str,
) -> Result<String, String> {
    crypto::pgp::import_secret_key_to_store(&app, key_path, passphrase).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn save_initial_config<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    api_id: &str,
    api_hash: &str,
    folder: &str,
    pgp_passphrase: &str,
    encrypt_db: bool,
) -> Result<(), String> {
    settings::save_initial_config(&app, api_id, api_hash, folder, pgp_passphrase, encrypt_db)
        .map_err(|e| e.to_string())
}

/// PGP check + Argon2 are slow: run off the main thread, and give up if
/// the app was locked meanwhile.
async fn do_unlock<R: tauri::Runtime>(app: tauri::AppHandle<R>, passphrase: String) -> Result<(), String> {
    let epoch = crate::zk::epoch(&app);
    let app2 = app.clone();
    let pass = zeroize::Zeroizing::new(passphrase);
    tauri::async_runtime::spawn_blocking(move || -> Result<(), String> {
        let key = state::get_my_key(&app2).map_err(|e| e.to_string())?;
        crypto::pgp::check_secret_key(&key, &pass).map_err(|e| e.to_string())?;
        crate::zk::unlock(&app2, &pass, epoch)?;
        if crate::zk::epoch(&app2) != epoch {
            crate::zk::lock(&app2);
            return Err("app was locked".into());
        }
        state::set_pgp_passphrase(&app2, &pass);
        Ok(())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn check_pgp_passphrase<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    passphrase: String,
) -> Result<(), String> {
    do_unlock(app, passphrase).await
}

/// Auto-lock (app went to background / user pressed lock): forget the
/// passphrase, the decrypted PGP key, the unlocked ZK engine and every
/// revealed chat, wipe decrypted files. TDLib keeps running so delivery is
/// not interrupted.
#[tauri::command]
pub fn lock_app<R: tauri::Runtime>(app: tauri::AppHandle<R>) {
    crate::zk::lock(&app);
    state::forget_secrets(&app);
    if let Err(e) = crypto::plaintext::wipe_plaintext_files(&app) {
        log::warn!("Unable to wipe decrypted files: {}", e);
    }
    crate::emit(&app, "app-locked", ());
}

#[tauri::command]
pub async fn unlock_app<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    passphrase: String,
) -> Result<(), String> {
    do_unlock(app, passphrase).await
}

#[tauri::command]
pub fn start_telegram_client<R: tauri::Runtime>(app: tauri::AppHandle<R>) {
    thread::spawn(move || {
        let mut client = Client::new();
        client.start(&app);
    });
}
