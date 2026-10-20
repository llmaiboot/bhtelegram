<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { store } from './store';
import { SecretChat } from './model';
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome';
import { faUser, faKey, faWarning } from '@fortawesome/free-solid-svg-icons';
import { getChatKeyCompleteInfo, getMyKeyFingerprint } from './services/pgp';
import { PublicKeyFingerprints } from './model';

let pgpIdKeyFingerprint = ref('');
let pgpEncryptionKeyFingerprint = ref('');
let pgpKeyArmored = ref('');
const myKey = ref<PublicKeyFingerprints | null>(null);

// Groups a fingerprint in blocks of 4 so it can be compared aloud.
function formatFingerprint(fp: string): string {
  return fp.toUpperCase().replace(/(.{4})(?=.)/g, '$1 ');
}

function closeModal() {
  store.toggleChatKeyModal();
}

const secretChat = computed<SecretChat | null>(() => {
  if (!store.selectedChat) {
    return null;
  }
  if (!store.selectedChat.secret) {
    return null;
  }
  const id = store.selectedChat.secret_chat_id as number;
  const secretChat = store.secretChatsMap[id];
  if (!secretChat) {
    return null;
  }
  return secretChat;
});

watch(() => store.selectedChatKey, async () => {
  if (!store.selectedChat) {
    return;
  }
  if (store.selectedChatKey) {
    const info = await getChatKeyCompleteInfo(store.selectedChat.id);
    pgpIdKeyFingerprint.value = info.id_key_fingerprint;
    pgpEncryptionKeyFingerprint.value = info.encryption_key_fingerprint;
    pgpKeyArmored.value = info.armored_data;
    try {
      myKey.value = await getMyKeyFingerprint();
    } catch {
      myKey.value = null;
    }
  } else {
    pgpIdKeyFingerprint.value = '';
    pgpEncryptionKeyFingerprint.value = '';
    pgpKeyArmored.value = '';
  }
});
</script>

<template>
  <div class="modal" :class="{ 'is-active': store.chatKeyModalActive }" id="secret-chat-key-modal">
    <div class="modal-background" @click="closeModal"></div>
    <div class="modal-card">
      <header class="modal-card-head p-2">
        <p class="modal-card-title mt-1">Chat keys</p>
        <button class="delete" aria-label="close" @click="closeModal"></button>
      </header>
      <section class="modal-card-body p-3">
        <div v-if="store.selectedChatKey" class="mb-4">
          <h4 class="subtitle has-text-centered mt-4">PGP chat key</h4>
          <div class="has-text-centered">
            <div>
              <FontAwesomeIcon :icon="faUser" />
              <code>{{ pgpIdKeyFingerprint.toUpperCase() }}</code>
            </div>
            <div class="is-size-7 is-italic">identity</div>
          </div>
          <div class="has-text-centered mt-2">
            <div>
              <FontAwesomeIcon :icon="faKey" />
              <code>{{ pgpEncryptionKeyFingerprint.toUpperCase() }}</code>
            </div>
            <div class="is-size-7 is-italic">encryption</div>
          </div>
          <div class="box mt-4" id="fingerprint-check">
            <p class="has-text-weight-bold mb-2">Verify fingerprints</p>
            <p class="is-size-7 mb-1">Your key (your peer must see this one for you):</p>
            <code class="is-block mb-3">{{ myKey ? formatFingerprint(myKey.primary) : '—' }}</code>
            <p class="is-size-7 mb-1">Peer key stored for this chat:</p>
            <code class="is-block">{{ formatFingerprint(pgpIdKeyFingerprint) }}</code>
            <p class="is-size-7 mt-2">Compare both values with your peer over a different channel (call, in person).
              If they differ, someone may be intercepting the conversation.</p>
          </div>
          <div class="mt-4 mb-5">
            <pre>{{ pgpKeyArmored }}</pre>
          </div>
        </div>
        <div v-if="secretChat">
          <h4 class="subtitle has-text-centered mt-4">Secret chat key</h4>
          <div class="is-clearfix">
            <div id="key-img-wrapper" class="is-clearfix">
              <div v-for="line in secretChat.key_hash_img" class="is-clearfix">
                <div v-for="cell in line" :class="`key-square key-color-${cell}`"></div>
              </div>
            </div>
          </div>
          <div class="mt-4 mb-3">
            <div class="has-text-centered" v-for="line in secretChat.key_hash_hex">
              <code>{{ line }}</code>
            </div>
          </div>
        </div>
        <div class="notification has-background-warning-soft">
          <FontAwesomeIcon :icon="faWarning" />
          To ensure that there is no MITM attack, you should check that these keys are the same of your peer ones using
          a trusted channel.
        </div>
      </section>
      <footer class="modal-card-foot p-2">
      </footer>
    </div>
  </div>
</template>

<style>
#key-img-wrapper {
  max-width: 300px;
  margin: 10px auto;
}

.key-square {
  width: 8.3333%;
  aspect-ratio: 1;
  float: left;
}

.key-color-0 {
  background-color: #FFFFFF;
}

.key-color-1 {
  background-color: #D5E6F3;
}

.key-color-2 {
  background-color: #2D5775;
}

.key-color-3 {
  background-color: #2F99C9;
}
</style>