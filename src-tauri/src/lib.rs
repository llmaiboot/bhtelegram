mod model;
mod files;
mod messages;
mod commands;
mod crypto;
mod settings;
mod state;
mod store;
mod telegram;
mod thumbnails;
mod zk;
use serde::Serialize;
use std::sync::Mutex;
use tauri::{Emitter, Manager};

use crate::files::set_allowed_files_paths;

#[cfg(mobile)]
static SUSPENDED_AT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
#[cfg(mobile)]
const AUTO_LOCK_SECS: u64 = 60;
#[cfg(mobile)]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_os::init())
        .plugin(tauri_plugin_store::Builder::new().build())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            commands::init::get_default_folder,
            commands::init::generate_pgp_key,
            commands::init::import_pgp_key,
            commands::init::save_initial_config,
            commands::init::check_pgp_passphrase,
            commands::init::start_telegram_client,
            commands::login::set_authentication_phone_number,
            commands::login::set_authentication_code,
            commands::login::resend_authentication_code,
            commands::login::request_qr_code_authentication,
            commands::login::set_authentication_password,
            commands::login::is_logged_in,
            commands::login::logout,
            commands::chats::load_chats,
            commands::chats::open_chat,
            commands::chats::close_chat,
            commands::chats::get_chat_history,
            commands::chats::send_message,
            commands::chats::delete_message,
            commands::chats::view_message,
            commands::chats::forward_message,
            commands::chats::get_replied_message,
            commands::chats::create_new_secret_chat,
            commands::chats::delete_chat,
            commands::chats::add_message_reaction,
            commands::chats::remove_message_reaction,
            commands::chats::share_public_key,
            commands::folders::create_chat_folder,
            commands::folders::delete_chat_folder,
            commands::folders::rename_chat_folder,
            commands::folders::add_chat_to_folder,
            commands::folders::remove_chat_from_folder,
            commands::files::download_file,
            commands::files::save_file,
            commands::pgp::get_my_key_fingerprint,
            commands::pgp::export_secret_key,
            commands::pgp::export_public_key,
            commands::pgp::load_public_key,
            commands::pgp::get_chat_key,
            commands::pgp::get_chat_key_complete_info,
            commands::pgp::save_chat_key,
            commands::pgp::remove_chat_key,
            commands::pgp::decrypt_file,
            commands::pgp::decrypt_pgp_text_message,
            commands::pgp::download_pgp_key_file,
            commands::pgp::change_passphrase,
            commands::pgp::set_chat_revealed,
            commands::pgp::is_chat_revealed,
            commands::pgp::hide_all_chats,
            commands::privacy::get_privacy_settings,
            commands::privacy::set_privacy_settings,
            commands::zk::zk_start_session,
            commands::zk::zk_accept_invite,
            commands::zk::zk_send_text,
            commands::zk::zk_end_session,
            commands::zk::zk_status,
            commands::zk::zk_set_verified,
            commands::init::lock_app,
            commands::init::unlock_app,
        ])
        .setup(|app| {
            app.manage(Mutex::new(state::AppState::new()));
            app.manage(zk::ZkState::default());
            set_allowed_files_paths(app.handle()).unwrap();
            // Leftovers of a previous session that did not exit cleanly.
            if let Err(e) = crypto::plaintext::wipe_plaintext_files(app.handle()) {
                log::warn!("Unable to wipe decrypted files: {}", e);
            }
            Ok(())
        })
        .on_window_event(|window, event| match event {
            // Auto-lock: the file picker also pauses the activity, so lock
            // only when the app stayed in background longer than a minute.
            #[cfg(mobile)]
            tauri::WindowEvent::Suspended => {
                SUSPENDED_AT.store(now_secs(), std::sync::atomic::Ordering::SeqCst);
            }
            #[cfg(mobile)]
            tauri::WindowEvent::Resumed => {
                let at = SUSPENDED_AT.swap(0, std::sync::atomic::Ordering::SeqCst);
                if at != 0 && now_secs().saturating_sub(at) >= AUTO_LOCK_SECS
                    && state::is_logged_in(window.app_handle())
                {
                    commands::init::lock_app(window.app_handle().clone());
                }
            }
            tauri::WindowEvent::CloseRequested { api, .. } => {
                log::trace!("CloseRequested {}", window.label());
                if window.label() == "main" {
                    if let Err(e) = crypto::plaintext::wipe_plaintext_files(window.app_handle()) {
                        log::warn!("Unable to wipe decrypted files: {}", e);
                    }
                    let client_id = state::get_client_id(window.app_handle());
                    if client_id != 0 {
                        state::request_close(window.app_handle());
                        trpl::run(async {
                            tdlib::functions::close(client_id)
                                .await
                                .unwrap_or_else(|err| {
                                    log::error!("Error closing client: {}", err.message);
                                });
                        });
                        api.prevent_close();
                    }
                }
            }
            _ => {}
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

pub fn emit<S: Serialize + Clone, R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    event: &str,
    payload: S,
) {
    log::trace!("Emitting event {}", event);
    app.emit(event, payload).unwrap_or_else(|err| {
        log::error!("Error emitting event: {}", err);
    });
}
