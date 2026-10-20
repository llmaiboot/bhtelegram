# Changelog

## Unreleased (BhTelegram)

* Forked from OmbraChat 0.4.1 and rebranded to BhTelegram
* Data folder changed to `~/.bhtelegram`, app id `com.llmaiboot.bhtelegram`
* PGP attachments are now named `bhtelegram-*`; `ombra-chat-*` ones are still recognized
* Privacy settings: read receipts and "online" status are off by default
* Secret view: PGP content is decrypted only on explicit reveal per chat (auto-decrypt optional)
* Decrypted attachments are wiped on startup, exit and on demand
* Side-by-side fingerprint verification in the chat keys dialog
* Fix: replacing or removing a chat key now invalidates the cached key
* Fix: database encryption key and api_hash are no longer printed in debug logs
* Test guarding crypto/telegram layer isolation

## 0.4.1

* Displayed private chat username and phone number
* Minor performance improvements

## 0.4.0

* Big refactoring, moving a lot of logic from front-end to back-end; this should improve stability when TDLib types are updated
* Improved file download; file <1MB are downloaded synchronously, while bigger ones asynchronously
* Added option to change PGP key passphrase
* Supported displaying of secret chat key
* Improved visualization of PGP keys
* Updated Tauri dependencies

## 0.3.5

* Fixed bug in sending document and photos

## 0.3.4

* Used tdlib 1.8.65 (fix missing field 'media' error)
* Fixed key not downloadable
* Added setting to disable right margin workaround
* Improved logging configurability

## 0.3.3

* implemented folders editing
* basic support for voice messages
* updated tdlib to 1.8.63
* updated most of the dependencies, including tauri and pgp

## 0.3.2

* added double checkmarks for read messages
* handled secret chats state
* fixed issue with "reply to" messages

## 0.3.1

* basic support for emoji message
* fixed bug caused by invalid "reply to" message
* added about modal
* added setting to display pictures using app window rather than system default app
* updated dependencies

## 0.3.0

⚠️ Breaking changes: you need to regenerate your keys. It is also better to delete the `~/.ombra-chat` folder and repeat the login.

* app was completely rewritten in Tauri (Rust + Vue.js), due to JavaFX inability to handle Wayland and touch events
* simplified key generation and key sharing
* supported dark theme
* supported chat deletion
* updated tdlib to 1.8.52

## 0.2.1

* fixed messages loading issue
* changed app icon and title when there are unread messages
* updated tdlib to 1.8.50

## 0.2.0

* enabled uploading of multiple files
* handled paste of files using Ctrl+V
* enabled drag and drop file upload
* implemented photo messages with thumbnail creation
* basic reaction support
* supported message forwarding
* supported reply to
* fixed several issues

## 0.1.0

Initial release.

* displaying chat folders
* text messages
* file upload and download
* viewing photos
* deleting messages
* secret chats
* tdlib encryption
* GPG support
* automatic selection of default folder
