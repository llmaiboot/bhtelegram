use crate::{
    state,
    store::{self, PrivacySettings},
    telegram,
};

#[tauri::command]
pub fn get_privacy_settings<R: tauri::Runtime>(app: tauri::AppHandle<R>) -> PrivacySettings {
    store::get_privacy_settings(&app)
}

#[tauri::command]
pub async fn set_privacy_settings<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    settings: PrivacySettings,
) -> Result<(), String> {
    store::set_privacy_settings(&app, &settings);
    if state::is_logged_in(&app) {
        telegram::privacy::apply_online_status(&app).await;
    }
    Ok(())
}
