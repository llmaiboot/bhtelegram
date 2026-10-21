use crate::crypto::zk::engine::{open_file, FileHeader, FILE_FLAG_VOICE};
use crate::model::{Message, ZkOpenedFile};
use crate::{files, state, zk};
use std::path::{Path, PathBuf};

/// Limit for one attachment (read fully into memory for AEAD).
const MAX_FILE_BYTES: u64 = 50 * 1024 * 1024;

fn random_name() -> String {
    hex::encode(crate::crypto::zk::vault::random_bytes::<8>())
}

/// Only the last path component, no separators or control characters.
fn safe_file_name(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or("");
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control() && *c != ':')
        .take(120)
        .collect();
    let clean = clean.trim_start_matches('.').trim().to_string();
    if clean.is_empty() {
        "file".into()
    } else {
        clean
    }
}

fn mime_for(name: &str) -> String {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    match ext.as_str() {
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "mp4" => "video/mp4",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "ogg" | "oga" => "audio/ogg",
        "webm" => "audio/webm",
        "pdf" => "application/pdf",
        "txt" => "text/plain",
        _ => "application/octet-stream",
    }
    .into()
}

async fn send_sealed<R: tauri::Runtime>(
    app: &tauri::AppHandle<R>,
    chat_id: i64,
    header: FileHeader,
    content: Vec<u8>,
    flags: u8,
) -> Result<Message, String> {
    let (blob, caption) = zk::with_engine(app, |e| e.encrypt_file(chat_id, &header, &content, flags))?;
    drop(content);
    // Ciphertext only; the real name lives inside the encrypted blob.
    let dir = PathBuf::from(crate::store::get_application_folder(app)).join("zk_out");
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let path = dir.join(format!("{}.bin", random_name()));
    std::fs::write(&path, &blob).map_err(|e| e.to_string())?;
    let content = tdlib::enums::InputMessageContent::InputMessageDocument(
        tdlib::types::InputMessageDocument {
            document: tdlib::types::InputDocument {
                document: tdlib::enums::InputFile::Local(tdlib::types::InputFileLocal {
                    path: path.to_string_lossy().into_owned(),
                }),
                thumbnail: None,
                disable_content_type_detection: true,
            },
            caption: Some(tdlib::types::FormattedText {
                text: caption,
                entities: vec![],
            }),
        },
    );
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
    Ok(crate::messages::parser::parse_message(app, &m))
}

/// Sends a local file through the secure session.
#[tauri::command]
pub async fn zk_send_file<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    chat_id: i64,
    path: String,
    caption: Option<String>,
) -> Result<Message, String> {
    let meta = std::fs::metadata(&path).map_err(|e| e.to_string())?;
    if meta.len() > MAX_FILE_BYTES {
        return Err("Файл больше 50 МБ".into());
    }
    let content = std::fs::read(&path).map_err(|e| e.to_string())?;
    let name = safe_file_name(&path);
    let header = FileHeader {
        mime: mime_for(&name),
        name,
        caption: caption.filter(|c| !c.trim().is_empty()),
    };
    send_sealed(&app, chat_id, header, content, 0).await
}

/// Sends a voice message recorded in the WebView (MediaRecorder bytes).
#[tauri::command]
pub async fn zk_send_voice<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    chat_id: i64,
    data: Vec<u8>,
    mime: String,
) -> Result<Message, String> {
    if data.is_empty() || data.len() as u64 > MAX_FILE_BYTES {
        return Err("bad recording".into());
    }
    let ext = if mime.contains("ogg") {
        "ogg"
    } else if mime.contains("mp4") {
        "m4a"
    } else {
        "webm"
    };
    let header = FileHeader {
        name: format!("voice.{}", ext),
        mime: mime.chars().take(60).collect(),
        caption: None,
    };
    send_sealed(&app, chat_id, header, data, FILE_FLAG_VOICE).await
}

/// Downloads and decrypts an attachment into the wiped `zk_plain` folder.
/// Refused while the chat is hidden.
#[tauri::command]
pub async fn zk_open_file<R: tauri::Runtime>(
    app: tauri::AppHandle<R>,
    chat_id: i64,
    message_id: i64,
) -> Result<ZkOpenedFile, String> {
    if !zk::is_revealed(&app, chat_id) {
        return Err("Encrypted content of this chat is hidden".into());
    }
    let client_id = state::get_client_id(&app);
    let tdlib::enums::Message::Message(m) = tdlib::functions::get_message(chat_id, message_id, client_id)
        .await
        .map_err(|e| e.message)?;
    let tdlib::enums::MessageContent::MessageDocument(doc) = &m.content else {
        return Err("not an encrypted attachment".into());
    };
    let key = zk::file_key(&app, &zk::envelope(&m), &doc.caption.text)?;
    let tdlib::enums::File::File(f) =
        tdlib::functions::download_file(doc.document.document.id, 1, 0, 0, true, client_id)
            .await
            .map_err(|e| e.message)?;
    if !f.local.is_downloading_completed {
        return Err("download failed".into());
    }
    let blob = std::fs::read(&f.local.path).map_err(|e| e.to_string())?;
    let (header, data) = open_file(&key, &blob)?;
    let dir = crate::crypto::plaintext::zk_plain_dir(&app).join(random_name());
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let target = dir.join(safe_file_name(&header.name));
    std::fs::write(&target, &data[..]).map_err(|e| e.to_string())?;
    let path = target.to_string_lossy().into_owned();
    files::allow_opening_file(&app, &path);
    Ok(ZkOpenedFile {
        path,
        name: header.name,
        mime: header.mime,
        caption: header.caption,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_names_are_sanitized() {
        assert_eq!(safe_file_name("/a/b/фото.jpg"), "фото.jpg");
        assert_eq!(safe_file_name("..\\..\\evil.sh"), "evil.sh");
        assert_eq!(safe_file_name("../../"), "file");
        assert_eq!(safe_file_name(".hidden"), "hidden");
        assert_eq!(safe_file_name("a\nb:c"), "abc");
        assert_eq!(mime_for("X.JPG"), "image/jpeg");
    }
}
