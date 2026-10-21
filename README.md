<h1 align="center">
  <img src="src/assets/bhtelegram-logo.svg" alt="BhTelegram logo" width="256" height="256"/>
  <br>
  BhTelegram
</h1>

<p align="center"><strong>Privacy-focused Telegram desktop client — fork of <a href="https://github.com/ombra-chat/ombra-chat">OmbraChat</a></strong></p>

> BhTelegram is a fork of OmbraChat by Sonia Zorba (zonia3000), distributed under the same GPLv3 license.
> PGP messages stay compatible with OmbraChat users: BhTelegram reads both `ombra-chat-*` and `bhtelegram-*` attachments.
> Note: OmbraChat users will see messages sent from BhTelegram as plain `.pgp` files, because OmbraChat only recognizes its own prefix.


> ⚠️ Alpha release! Expect to find bugs and missing features!

BhTelegram is a desktop client for Telegram designed for privacy-conscious nerds.

In addition to supporting secret chats and encrypting Telegram's local database, it offers some extra features like:

* The ability to associate a PGP key with a user, allowing to encrypt all standard one-on-one chats (which are not encrypted by default in Telegram). PGP encryption can also be activated within secret chats, providing an additional layer of encryption. Messages sent from a standard Telegram client will appear as .pgp files (see the screenshot below).

* An option to define a default chat group (folder) that is automatically selected when the app starts; this can be useful if you want to hide certain chats from prying eyes when opening the client.

* Deliberately avoid useless features like AI and animated stickers, as they just increase the attack surface without adding real value.

Following screenshot displays how the PGP messages are seen in BhTelegram/OmbraChat and in the standard Telegram client:

![ombra-chat vs telegram](screenshots/ombra-chat-comparison.png)

> ⚠️ **Disclaimer**: this app is currently a pet project and I'm not a cryptographer, so do not rely on it for highly sensitive data.

The original app is named OmbraChat because "ombra" means "shadow" in Italian.

Currently it has been tested only on Linux, but it could work also on other OS.

Fork source code: [GitHub](https://github.com/llmaiboot/bhtelegram). Upstream: [GitHub](https://github.com/ombra-chat/ombra-chat) / [Codeberg](https://codeberg.org/zonia3000/ombra-chat).

## BhTelegram privacy defaults

Ideas adopted from [zkgram](https://github.com/Gerate-Technik/zkgram), adapted to the PGP model of this client:

| Feature | Default | Where |
|---|---|---|
| Read receipts are not sent to Telegram | on | Settings → Privacy |
| "Online" status is not reported | on | Settings → Privacy |
| Secret view: PGP messages are decrypted only after pressing the eye button in a chat, never automatically; hidden content carries no plaintext, not even file names | on | Chat header / Settings → Privacy |
| Decrypted attachments are wiped from disk on startup, on exit and on "Hide all encrypted content now" | always | — |
| Fingerprint check: your key and the peer key are shown side by side, grouped by 4 characters, to be compared over another channel | always | Chat keys dialog |
| Secrets (`api_hash`, database key) are redacted from logs | always | — |

### Layer isolation

`src-tauri/src/crypto` (keys, plaintext) never imports TDLib or `telegram`, and `src-tauri/src/telegram` (transport) never imports `crypto`/`pgp`. Only `commands` and `messages` connect them. This is enforced by `src-tauri/tests/layers.rs`.

### What BhTelegram does not protect against

| Not protected | Why |
|---|---|
| Metadata | Telegram still sees who talks to whom and when; only message content is hidden. |
| "Last seen" when you send | The online flag is kept off, but Telegram can still update your last-seen time when you actively send messages. |
| A compromised device | Malware running while the passphrase is entered or content is revealed can read it. |
| Skipped fingerprint check | Without comparing fingerprints out of band, a swapped key (MITM) goes unnoticed. |
| Past messages after a key leak | PGP has no forward secrecy: a leaked private key decrypts all previous messages. |
| SSD/CoW remnants | Wiped files are overwritten before deletion, but SSDs and copy-on-write filesystems may keep old blocks. |

## Secure chats (zero-knowledge mode)

Idea and threat model from [zkgram](https://github.com/Gerate-Technik/zkgram): Telegram is an untrusted wire and must only ever see ciphertext. The protocol is different: instead of a hand-made ECDH + AES scheme BhTelegram uses the audited **Olm Double Ratchet** (Signal-style, [vodozemac](https://github.com/matrix-org/vodozemac) by Matrix).

| Property | How |
|---|---|
| End-to-end encryption, per-message keys | Olm Double Ratchet: every message has its own key; leaking today's keys does not reveal past messages (forward secrecy) and the session heals itself (post-compromise security) |
| No key exchange through files | Shield button → an invitation with public keys (Ed25519 + Curve25519 + one-time key, signed) is sent as a normal message; the peer taps "Accept" |
| MITM protection | 60-digit safety number, identical on both phones; compare it by voice and press "Codes match". If the peer's identity changes the shield turns red |
| Ciphertext disguise | Bytes are encoded as Russian words (WordCoder dictionary from zkgram), Telegram sees a line of words, not base64 |
| Local data | Identity, ratchet state and decrypted history encrypted with Argon2id (from the passphrase) + XChaCha20-Poly1305; nothing in plaintext on disk |
| Secret view | Decrypted text is shown only after the eye button, as for PGP |
| Phone | No screenshots / recent-apps preview (FLAG_SECURE), no cloud backup, auto-lock after 60 s in background, Lock item in the menu |

Limits: only text for now (files go through PGP), messages are readable only on the device that received them (no multi-device), metadata (who talks to whom and when) stays visible to Telegram. Both sides need BhTelegram.

The engine (`src-tauri/src/crypto/zk`) has no dependency on Tauri or TDLib (enforced by `tests/layers.rs`) and is covered by end-to-end tests: handshake, out-of-order delivery, restart, tampering, key change, chunking, re-keying.

## Implemented features

* Text messages
* Photo messages
* Document messages
* Sharing of documents using drag and drop
* PGP encrypted text and document messages
* Easy sharing and trusting of public PGP keys
* Basic secret chats support (still buggy)
* Encrypted Telegram's local database
* Selection of default chat folder
* Chat folders creation and editing
* Chat deletion
* Basic reactions
* Emoji messages (read-only, not animated)
* Listening of voice messages (not sending)
* Light/Dark theme

## Why?

There are numerous open-source messaging applications that offer robust end-to-end encryption support. However, the existence of multiple options often leads to fragmentation, with users reluctant to create numerous accounts. Consequently, even tech-savvy individuals tend to use mostly Telegram, where encrypted chats are not created by default and not supported by the official desktop client.

This alternative client allows us to continue utilizing Telegram's infrastructure while addressing its privacy limitations. While PGP may not be user-friendly and lacks features like forward secrecy, it is still better than standard unencrypted chats. On the other hand, it's nice to have direct control over your keys instead of depending on automatic mechanisms that can be somewhat unclear.

Moreover, switching to alternative clients with their own encryption will create resistance against the rising governmental push to invade our private conversations (yes, I'm looking at you, "Chat Control 2.0").

## Install

Check the [latest release](https://github.com/llmaiboot/bhtelegram/releases) for some pre-built binaries.

If you install the .deb or .rpm you will also need the libtdjson.so file. You can download it from the release page and copy it into `/usr/lib` or other proper location.

If you are using Wayland, install the .deb or .rpm rather than the AppImage, since Tauri's AppImage doesn't work well with Wayland (see https://github.com/tauri-apps/tauri/issues/11790).

## Configure PGP keys

### Setup your private key

During the initial configuration the app generates a PGP keypair for you. You should provide a password to encrypt the key. You have to insert this password to decrypt the key every time the app is started.

![initial configuration](screenshots/ombra-chat-initial-config.png)

The keypair uses Curve25519 and is generated using [rPGP](https://github.com/rpgp/rpgp). You can also import an externally generated key, but consider that keys generated with GnuPG may not be fully compatible. The purpose of the "Select PGP key" button is mostly to import a key generated with BhTelegram/OmbraChat on a different device.

Once the app is started, you can export your key from the settings modal:

![export your key](screenshots/ombra-chat-export-key.png)

### Associate a chat with a public key

To share your public key to a friend, go to their chat, open the chat settings modal and click on the "Share public key" button.

![share your key](screenshots/ombra-chat-share-key.png)

A special message is sent. Your friend can accept the key directly on the "Use this key" button. The new messages will be encrypted using that key. Your friend has to share their key too and you have to accept it. Ideally, you should check the keys on an external trusted channel.

![use shared key](screenshots/ombra-chat-use-key.png)

It is also possible to manually import a key from file.

## Application data

The application stores its data in a folder that can be configured during the first setup. The default location is `~/.bhtelegram`.

Preferences are stored in `~/.local/share/com.llmaiboot.bhtelegram`.

## Android

BhTelegram also builds for Android (Tauri 2 mobile). Tested on an x86_64 emulator (Android 14).

1. Build TDLib for Android once (~30 min, arm64-v8a + x86_64):
   ```bash
   git clone https://github.com/tdlib/td.git ~/projects/td && git -C ~/projects/td checkout a9966eb3704a3351568c28013fed67d797c17828
   ./scripts/build-tdlib-android.sh ~/projects/td ~/projects/bhtelegram-deps/android
   ```
2. Requirements: Android SDK + NDK 29 (`$ANDROID_HOME`, `$NDK_HOME`), JDK 21, rustup with
   `aarch64-linux-android` and `x86_64-linux-android` targets. `tdlib-rs` (branch `bhtelegram-mobile` of github.com/llmaiboot/tdlib-rs) must contain the
   `TDJSON_LIB_DIR` support in `tdlib/build.rs` (mobile targets skip pkg-config).
3. Build:
   ```bash
   export TDJSON_LIB_DIR=~/projects/bhtelegram-deps/android
   npx tauri android build --apk --target aarch64 --target x86_64
   ```
   Release signing reads `src-tauri/gen/android/keystore.properties` (`storeFile`, `keyAlias`, `password`); the file is git-ignored.

On phones the data folder is the app-private storage, extra photo windows, window titles and drag & drop are disabled.

## Developing

Build tdlib using following instructions: https://tdlib.github.io/td/build.html?language=C

Alternatively, you can download the libtdjson.so from the [release page](https://github.com/llmaiboot/bhtelegram/releases). You may need to configure the pkg-config file, like `/usr/local/lib/pkgconfig/tdjson.pc`:

```
prefix=/usr/local

Name: tdjson
Description: Telegram Library - JSON interface (shared)
Version: 1.8.65

CFlags: -I"${prefix}/include"
Libs: -L"${prefix}/lib" -ltdjson
Requires.private: tdjson_private
```

Clone tdlib-rs in a folder at the same level of the bhtelegram repo folder:

```sh
git clone https://github.com/ombra-chat/tdlib-rs.git
```

Install [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/), then clone this repo and install the app dependencies:

```bash
git clone https://github.com/llmaiboot/bhtelegram.git
cd bhtelegram
npm install
```

To run in developer mode:

```bash
npm run tauri dev
```

To build release packages:

```bash
npm run tauri build
```

## Debug

You can use the following environment variables to increase the logging. Notice that TDLib logging can be split from all the other logging, since the library can produce a very verbose output.

* `RUST_LOG=bhtelegram_lib=trace`: standard Rust logging;
* `TDLIB_LOG_LEVEL=3`: TDLib logging; values are:
    * 0: fatal errors
    * 1: errors
    * 2: warnings and debug warnings
    * 3: informational (this is usually verbose enough)
    * 4: debug
    * 5: trace
* `TDLIB_LOG_FILE`: path to a file where to redirect TDLib logs (instead of using stdout)

If `TDLIB_LOG_LEVEL` is not specified, it fallbacks to the `RUST_LOG` level.

Be also aware that TDLib log may contain sensitive data in plaintext.

## AI policy

LLM contributions are **not** welcome and it is forbidden to use this code to train AI models.

DuckDuckGo AI has been used sporadically in this project to improve some sentences in this README file and to receive some suggestions about Rust syntax. DuckDuckGo states that it doesn't use the data to further train the AI.

The maintainer of this project is concerned about ethical issues related to AI and tries to use it as little as possibile.

## License

BhTelegram, like the original OmbraChat, is released under GPLv3.

The app is based on [tdlib](https://github.com/tdlib/td) released with Boost Software License - copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2025
