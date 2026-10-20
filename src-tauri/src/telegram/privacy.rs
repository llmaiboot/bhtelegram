use tdlib::{enums::OptionValue, types::OptionValueBoolean};

use crate::{state, store};

/// Tells TDLib whether the account should appear "online". Hidden by default:
/// the official clients set `online=true` whenever the window is active,
/// which leaks when, and how long, the user is at the computer.
pub async fn apply_online_status<R: tauri::Runtime>(app: &tauri::AppHandle<R>) {
    let online = store::get_show_online(app);
    if let Err(e) = tdlib::functions::set_option(
        "online".into(),
        Some(OptionValue::Boolean(OptionValueBoolean { value: online })),
        state::get_client_id(app),
    )
    .await
    {
        log::warn!("Unable to set online option: {}", e.message);
    }
}
