use crate::{
    crypto::{self, pgp},
    state, store,
};
use std::{env, error::Error, fs, path::PathBuf};

pub fn get_default_bhtelegram_folder() -> Option<PathBuf> {
    if let Some(home_dir) = env::home_dir() {
        let mut pgp_path = home_dir;
        pgp_path.push(".bhtelegram");
        Some(pgp_path)
    } else {
        None
    }
}

pub fn get_default_folder<R: tauri::Runtime>(app: &tauri::AppHandle<R>) -> String {
    // On phones there is no usable home directory: keep data in the
    // app-private storage (/data/data/<id>/files on Android, sandbox on iOS).
    #[cfg(mobile)]
    {
        use tauri::Manager;
        if let Ok(dir) = app.path().app_data_dir() {
            return dir.join("bhtelegram").to_string_lossy().into_owned();
        }
    }
    #[cfg(desktop)]
    let _ = app;
    get_default_bhtelegram_folder()
        .map(|path| path.to_string_lossy().into_owned())
        .unwrap_or_else(|| String::new())
}

pub fn save_initial_config<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    api_id: &str,
    api_hash: &str,
    folder: &str,
    pgp_password: &str,
    encrypt_db: bool,
) -> Result<(), Box<dyn Error>> {
    log::trace!("save_initial_config");

    let key = state::get_my_key(app)?;
    pgp::check_secret_key(&key, pgp_password)?;

    let api_id: i32 = api_id.parse::<i32>()?;

    let mut encrypted_password: Option<String> = None;
    if encrypt_db {
        let password = crypto::utils::generate_random_password();
        let key = pgp::get_encryption_key_from_secret_key(&key)?;
        let password = pgp::encrypt_string_to_string(&vec![key], &password)?;
        encrypted_password = Some(password.to_string());
    }

    // Create the app directory if it doesn't exist
    fs::create_dir_all(folder)?;

    // Save configuration
    store::set_api_id(app, api_id);
    store::set_api_hash(app, api_hash);
    store::set_application_folder(app, folder);
    store::set_encrypt_database(app, encrypt_db);
    if encrypt_db && encrypted_password.is_some() {
        store::set_encrypted_database_password(app, &encrypted_password.unwrap());
        store::set_encryption_salt(app, &crypto::utils::generate_random_salt());
    }
    store::set_initial_config_done(app, true);

    crate::zk::unlock(app, pgp_password)?;
    state::set_pgp_passphrase(app, pgp_password);

    Ok(())
}

pub struct TdlibParameters {
    pub database_directory: String,
    pub api_id: i32,
    pub api_hash: String,
    pub database_encryption_key: String,
}

// Secrets (api_hash, the derived database key) must never reach the logs:
// RUST_LOG=debug used to print the database encryption key in plaintext.
impl std::fmt::Debug for TdlibParameters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TdlibParameters")
            .field("database_directory", &self.database_directory)
            .field("api_id", &self.api_id)
            .field("api_hash", &"<redacted>")
            .field(
                "database_encryption_key",
                &if self.database_encryption_key.is_empty() {
                    "<none>"
                } else {
                    "<redacted>"
                },
            )
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tdlib_parameters_debug_hides_secrets() {
        let params = TdlibParameters {
            database_directory: "/tmp/db".into(),
            api_id: 42,
            api_hash: "super-secret-hash".into(),
            database_encryption_key: "deadbeefcafebabe".into(),
        };
        let out = format!("{:?}", params);
        assert!(!out.contains("super-secret-hash"));
        assert!(!out.contains("deadbeefcafebabe"));
        assert!(out.contains("/tmp/db"));
        assert!(out.contains("<redacted>"));
    }
}

pub fn get_tdlib_parameters<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
) -> Result<TdlibParameters, Box<dyn Error>> {
    log::trace!("get_tdlib_parameters");

    let application_folder = store::get_application_folder(app);

    let mut database_directory = PathBuf::from(application_folder);
    database_directory.push("tdlib");
    let database_directory = database_directory.to_string_lossy().to_string();

    // Create the database directory if it doesn't exist
    fs::create_dir_all(database_directory.to_string())?;

    let api_id = store::get_api_id(app);
    let api_hash = store::get_api_hash(app);

    let encrypt_database = store::get_encrypt_database(app);

    let mut database_encryption_key = String::new();
    if encrypt_database {
        let encrypted_password = store::get_encrypted_database_password(app);
        let password = pgp::decrypt_string_to_string(app, &encrypted_password)?;
        let salt = store::get_encryption_salt(app);
        database_encryption_key = crypto::utils::generate_derived_key(&password, &salt)?;
    }

    let params = TdlibParameters {
        database_directory,
        api_id,
        api_hash,
        database_encryption_key,
    };
    log::debug!("TdlibParameters: {:#?}", params);
    Ok(params)
}
