use crate::telegram::{chats, effects, folders, messages, users};
use crate::{emit, settings, state};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::sync::{atomic::AtomicBool, mpsc::channel};
use std::{env, thread};
use tdlib::enums::OptionValue;
use tdlib::types::LogStreamFile;

pub struct Client {
    client_id: i32,
}

impl Client {
    pub fn new() -> Self {
        Client {
            client_id: tdlib::create_client(),
        }
    }

    pub fn start<R: tauri::Runtime>(&mut self, app: &tauri::AppHandle<R>) {
        let (tx, rx) = channel::<tdlib::enums::Update>();
        let client_id = self.client_id;
        let close = Arc::new(AtomicBool::new(false));

        state::set_client_id(app, client_id);

        let close_clone = close.clone();
        let receive_handler = thread::spawn(move || {
            while !close_clone.load(Ordering::Relaxed) {
                if let Some((update, _client_id)) = tdlib::receive() {
                    if let Err(e) = tx.send(update) {
                        log::error!("Error sending update through the channel: {}", e);
                    }
                }
            }
            log::trace!("tdlib::receive loop ended");
        });
        thread::spawn(move || init(client_id));
        while let Ok(update) = rx.recv() {
            trpl::run(async {
                self.handle_update(app, update).await;
            });
            if state::close_requested(app) {
                break;
            }
        }
        log::trace!("rx.recv loop ended");
        close.store(true, Ordering::SeqCst);

        receive_handler.join().unwrap_or_else(|_| {
            log::error!("Unable to join receive handler");
        });
        log::trace!("exit(0)");
        app.exit(0);
    }

    async fn handle_update<R: tauri::Runtime>(
        &mut self,
        app: &tauri::AppHandle<R>,
        update: tdlib::enums::Update,
    ) {
        use tdlib::enums::AuthorizationState;
        use tdlib::enums::Update;

        if chats::handle_chats_update(app, &update) {
            return;
        }
        if folders::handle_folders_update(app, &update) {
            return;
        }
        if messages::handle_messages_update(app, &update) {
            return;
        }
        if users::handle_users_update(app, &update) {
            return;
        }
        if effects::handle_effects_update(app, &update).await {
            return;
        }

        match update {
            Update::AuthorizationState(state) => match state.authorization_state {
                AuthorizationState::WaitTdlibParameters => {
                    self.send_tdlib_parameters(app).await;
                }
                AuthorizationState::WaitPhoneNumber => {
                    emit(app, "ask-login-phone-number", ());
                }
                AuthorizationState::WaitCode(wait) => {
                    emit(app, "ask-login-code", login_code_info(&wait.code_info));
                }
                AuthorizationState::WaitOtherDeviceConfirmation(wait) => {
                    emit(app, "ask-login-qr", wait.link);
                }
                AuthorizationState::WaitPassword { .. } => {
                    emit(app, "ask-login-password", ());
                }
                AuthorizationState::Ready => {
                    state::set_logged_in(app, true);
                    super::privacy::apply_online_status(app).await;
                    emit(app, "logged-in", ());
                }
                AuthorizationState::LoggingOut | AuthorizationState::Closing => {
                    log::trace!("authorization state {:?}", state);
                    // ignored
                }
                AuthorizationState::Closed => {
                    state::request_close(app);
                }
                _ => {
                    log::warn!("Unsupported authorization state {:?}", state);
                }
            },
            Update::Option(option) => {
                if option.name == "my_id" {
                    if let OptionValue::Integer(value) = option.value {
                        state::set_my_id(&app, value.value);
                        emit(app, "my-id", value.value);
                    }
                }
            }
            _ => {
                // TODO
            }
        }
    }

    async fn send_tdlib_parameters<R: tauri::Runtime>(&self, app: &tauri::AppHandle<R>) {
        log::trace!("send_tdlib_parameters");

        let params = match settings::get_tdlib_parameters(app) {
            Ok(s) => s,
            Err(e) => {
                log::error!("Error retrieving tdlib parameters: {}", e);
                return;
            }
        };

        tdlib::functions::set_tdlib_parameters(
            false,
            params.database_directory,
            String::new(),
            params.database_encryption_key,
            true,
            true,
            true,
            true,
            params.api_id,
            params.api_hash,
            "en".into(),
            "Desktop".into(),
            String::new(),
            "1.0".into(),
            self.client_id,
        )
        .await
        .unwrap_or_else(|err| {
            log::error!("Error setting tdlib_parameters: {}", err.message);
        });
    }
}

fn init(client_id: i32) {
    trpl::run(async {
        set_tdlib_log_verbosity_level(client_id).await;
        set_tdlib_log_to_file(client_id).await;

        if let Err(e) = tdlib::functions::get_option("version".into(), client_id).await {
            log::warn!("Error retrieving the tdlib version: {:?}", e);
        }
    });
}

async fn set_tdlib_log_verbosity_level(client_id: i32) -> () {
    let verbosity_level = match env::var("TDLIB_LOG_LEVEL") {
        Ok(val) => match val.parse::<i32>() {
            Ok(level) => Some(level),
            Err(_) => {
                log::warn!("Unexpected value in TDLIB_LOG_LEVEL: {:?}", val);
                None
            }
        },
        Err(_) => None,
    };
    let verbosity_level = verbosity_level.unwrap_or_else(|| {
        // Use the main logger level as fallback
        if log::log_enabled!(log::Level::Trace) {
            5
        } else if log::log_enabled!(log::Level::Debug) {
            4
        } else if log::log_enabled!(log::Level::Info) {
            3
        } else if log::log_enabled!(log::Level::Warn) {
            2
        } else {
            0
        }
    });

    if let Err(e) = tdlib::functions::set_log_verbosity_level(verbosity_level, client_id).await {
        log::warn!("Error setting the tdlib log level: {:?}", e);
    }
}

async fn set_tdlib_log_to_file(client_id: i32) -> () {
    if let Ok(log_file_path) = env::var("TDLIB_LOG_FILE") {
        let log_stream = tdlib::enums::LogStream::File(LogStreamFile {
            path: log_file_path,
            max_file_size: 10 * 1024 * 1024,
            redirect_stderr: false,
        });
        if let Err(e) = tdlib::functions::set_log_stream(log_stream, client_id).await {
            log::warn!("Error setting the tdlib log stream: {:?}", e);
        }
    }
}

/// What the login screen needs to tell the user where the code went.
#[derive(serde::Serialize, Clone)]
pub struct LoginCodeInfo {
    pub phone_number: String,
    /// telegram_message | sms | call | flash_call | missed_call | fragment | firebase | unknown
    pub delivery: String,
    pub next_delivery: Option<String>,
    pub length: i32,
    /// Seconds before the code can be re-sent
    pub timeout: i32,
}

fn code_delivery(t: &tdlib::enums::AuthenticationCodeType) -> (&'static str, i32) {
    use tdlib::enums::AuthenticationCodeType as T;
    match t {
        T::TelegramMessage(c) => ("telegram_message", c.length),
        T::Sms(c) => ("sms", c.length),
        T::SmsWord(_) | T::SmsPhrase(_) => ("sms", 0),
        T::Call(c) => ("call", c.length),
        T::FlashCall(_) => ("flash_call", 0),
        T::MissedCall(c) => ("missed_call", c.length),
        T::Fragment(c) => ("fragment", c.length),
        T::FirebaseAndroid(c) => ("firebase", c.length),
        T::FirebaseIos(c) => ("firebase", c.length),
    }
}

fn login_code_info(info: &tdlib::types::AuthenticationCodeInfo) -> LoginCodeInfo {
    let (delivery, length) = code_delivery(&info.r#type);
    LoginCodeInfo {
        phone_number: info.phone_number.clone(),
        delivery: delivery.into(),
        next_delivery: info.next_type.as_ref().map(|t| code_delivery(t).0.to_string()),
        length,
        timeout: info.timeout,
    }
}
