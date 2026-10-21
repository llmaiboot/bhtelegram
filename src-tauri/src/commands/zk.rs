use crate::crypto::zk::engine::ChatStatus;
use crate::messages::parser::parse_message;
use crate::model::Message;
use crate::{state, zk};

async fn send_text<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    chat_id: i64,
    text: String,
) -> Result<Message, String> {
    let content = tdlib::enums::InputMessageContent::InputMessageText(tdlib::types::InputMessageText {
        text: tdlib::types::FormattedText {
            text,
            entities: vec![],
        },
        link_preview_options: Some(tdlib::types::LinkPreviewOptions {
            is_disabled: true,
            url: String::new(),
            force_small_media: false,
            force_large_media: false,
            show_above_text: false,
        }),
        clear_draft: true,
    });
    let tdlib::enums::Message::Message(m) = tdlib::functions::send_message(
        chat_id,
        None,
        None,
        None,
        None,
        content,
        state::get_client_id(app),
    )
    .await
    .map_err(|e| e.message)?;
    Ok(parse_message(app, &m))
}

/// Sends an invitation (public keys only) to start a secure session.
#[tauri::command]
pub async fn zk_start_session<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    chat_id: i64,
) -> Result<Message, String> {
    let text = zk::with_engine(&app, |e| e.create_invite())?;
    send_text(&app, chat_id, text).await
}

#[tauri::command]
pub async fn zk_accept_invite<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    chat_id: i64,
    message_id: i64,
) -> Result<Message, String> {
    let tdlib::enums::Message::Message(m) =
        tdlib::functions::get_message(chat_id, message_id, state::get_client_id(&app))
            .await
            .map_err(|e| e.message)?;
    let tdlib::enums::MessageContent::MessageText(content) = &m.content else {
        return Err("not an invitation".into());
    };
    let env = zk::envelope(&m);
    let reply = zk::with_engine(&app, |e| e.accept_invite(&env, &content.text.text))?;
    send_text(&app, chat_id, reply).await
}

#[tauri::command]
pub async fn zk_send_text<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    chat_id: i64,
    text: String,
) -> Result<Vec<Message>, String> {
    if text.trim().is_empty() {
        return Ok(vec![]);
    }
    let parts = zk::with_engine(&app, |e| e.encrypt_text(chat_id, &text))?;
    let mut out = Vec::with_capacity(parts.len());
    for p in parts {
        out.push(send_text(&app, chat_id, p).await?);
    }
    Ok(out)
}

#[tauri::command]
pub async fn zk_end_session<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    chat_id: i64,
) -> Result<Message, String> {
    let text = zk::with_engine(&app, |e| e.end_session(chat_id))?;
    // Keys are dropped only once the peer can learn the session ended.
    let msg = send_text(&app, chat_id, text).await?;
    zk::with_engine(&app, |e| e.forget_sessions(chat_id))?;
    Ok(msg)
}

/// The user accepts a changed peer identity without comparing codes.
#[tauri::command]
pub fn zk_accept_new_peer<R: tauri::Runtime>(app: tauri::AppHandle<R>, chat_id: i64) -> Result<(), String> {
    zk::with_engine(&app, |e| e.accept_new_peer(chat_id))
}

/// The user rejects a changed peer identity (possible attack).
#[tauri::command]
pub fn zk_reject_new_peer<R: tauri::Runtime>(app: tauri::AppHandle<R>, chat_id: i64) -> Result<(), String> {
    zk::with_engine(&app, |e| e.reject_new_peer(chat_id))
}

/// Drops decrypted history of a closed chat from memory.
#[tauri::command]
pub fn zk_unload_chat<R: tauri::Runtime>(app: tauri::AppHandle<R>, chat_id: i64) {
    let _ = zk::with_engine(&app, |e| {
        e.unload_chat(chat_id);
        Ok(())
    });
}

#[tauri::command]
pub fn zk_status<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    chat_id: i64,
) -> Result<ChatStatus, String> {
    zk::with_engine(&app, |e| e.status(chat_id))
}

#[tauri::command]
pub fn zk_set_verified<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    chat_id: i64,
    verified: bool,
) -> Result<(), String> {
    zk::with_engine(&app, |e| e.set_verified(chat_id, verified))
}
