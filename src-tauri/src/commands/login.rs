use crate::state;

#[tauri::command]
pub async fn set_authentication_phone_number<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    phone_number: &str,
) -> Result<(), String> {
    tdlib::functions::set_authentication_phone_number(
        String::from(phone_number),
        None,
        state::get_client_id(&app),
    )
    .await
    .map_err(|e| e.message)
}

#[tauri::command]
pub async fn set_authentication_code<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    code: &str,
) -> Result<(), String> {
    tdlib::functions::check_authentication_code(String::from(code), state::get_client_id(&app))
        .await
        .map_err(|e| e.message)
}

#[tauri::command]
pub async fn set_authentication_password<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    password: &str,
) -> Result<(), String> {
    tdlib::functions::check_authentication_password(
        String::from(password),
        state::get_client_id(&app),
    )
    .await
    .map_err(|e| e.message)
}

#[tauri::command]
pub fn is_logged_in<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> Result<bool, String> {
    Ok(state::is_logged_in(&app))
}

#[tauri::command]
pub async fn logout<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> Result<(), String> {
    tdlib::functions::log_out(state::get_client_id(&app))
        .await
        .map_err(|e| e.message)
}

/// Asks Telegram to send the code again, using `next_type` (usually SMS or a call).
#[tauri::command]
pub async fn resend_authentication_code<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> Result<(), String> {
    tdlib::functions::resend_authentication_code(
        Some(tdlib::enums::ResendCodeReason::UserRequest),
        state::get_client_id(&app),
    )
    .await
    .map_err(|e| e.message)
}

/// Switches to QR login: confirm it from Telegram on a phone
/// (Settings > Devices > Link Desktop Device). No code is needed.
#[tauri::command]
pub async fn request_qr_code_authentication<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
) -> Result<(), String> {
    tdlib::functions::request_qr_code_authentication(vec![], state::get_client_id(&app))
        .await
        .map_err(|e| e.message)
}
