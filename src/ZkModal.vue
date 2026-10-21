<script setup lang="ts">
import { ref } from 'vue';
import { store } from './store';
import { zkAcceptNewPeer, zkEndSession, zkRejectNewPeer, zkSetVerified, zkStatus } from './services/zk';

async function decideNewPeer(accept: boolean) {
  if (!store.selectedChat) return;
  error.value = '';
  try {
    if (accept) {
      await zkAcceptNewPeer(store.selectedChat.id);
    } else {
      await zkRejectNewPeer(store.selectedChat.id);
    }
    store.selectedZk = await zkStatus(store.selectedChat.id);
  } catch (err) {
    error.value = err as string;
  }
}

const error = ref('');

function close() {
  store.zkModalActive = false;
}

async function setVerified(v: boolean) {
  if (!store.selectedChat) return;
  error.value = '';
  try {
    await zkSetVerified(store.selectedChat.id, v);
    store.selectedZk = await zkStatus(store.selectedChat.id);
  } catch (err) {
    error.value = err as string;
  }
}

async function endSession() {
  if (!store.selectedChat) return;
  if (!confirm('Завершить защищённый сеанс? Ключи сеанса будут удалены.')) return;
  error.value = '';
  try {
    await zkEndSession(store.selectedChat.id);
    store.selectedZk = await zkStatus(store.selectedChat.id);
    close();
  } catch (err) {
    error.value = err as string;
  }
}
</script>

<template>
  <div class="modal" :class="{ 'is-active': store.zkModalActive }">
    <div class="modal-background" @click="close"></div>
    <div class="modal-card">
      <header class="modal-card-head p-2">
        <p class="modal-card-title mt-1">Защищённый чат</p>
        <button class="delete" aria-label="close" @click="close"></button>
      </header>
      <section class="modal-card-body p-3" v-if="store.selectedZk">
        <div v-if="store.selectedZk.peer_changed" class="notification is-danger p-3">
          Ключ собеседника изменился. Это бывает при переустановке приложения, но может означать
          подмену. Отправка заблокирована: сверьте новый код с собеседником голосом.
          <div class="buttons mt-2">
            <button class="button is-small is-danger" @click="() => decideNewPeer(false)">Отклонить (вернуть старый ключ)</button>
            <button class="button is-small" @click="() => decideNewPeer(true)">Принять без проверки</button>
          </div>
        </div>
        <p class="mb-2">Код безопасности. Сравните его с собеседником лично или по другому каналу
          (звонок). Если цифры совпадают, посредника нет.</p>
        <pre class="safety-number has-text-centered">{{ store.selectedZk.safety_number }}</pre>
        <p class="mt-3">
          Статус:
          <strong :class="store.selectedZk.verified ? 'has-text-success' : 'has-text-warning'">
            {{ store.selectedZk.verified ? 'проверен' : 'не проверен' }}
          </strong>
        </p>
        <p class="is-size-7 has-text-grey mt-3">
          Протокол Olm Double Ratchet (vodozemac): новый ключ на каждое сообщение, прошлые сообщения не
          расшифровать даже при утечке текущих ключей. Telegram видит только набор слов.
          Сообщения читаются только на этом устройстве.
        </p>
        <p v-if="error" class="has-text-danger mt-2">{{ error }}</p>
      </section>
      <footer class="modal-card-foot p-2 is-flex is-flex-wrap-wrap" style="gap: .5rem">
        <button v-if="store.selectedZk && !store.selectedZk.verified" class="button is-success"
          @click="() => setVerified(true)">Коды совпадают</button>
        <button v-if="store.selectedZk && store.selectedZk.verified" class="button"
          @click="() => setVerified(false)">Снять отметку</button>
        <button class="button is-danger is-outlined" @click="endSession">Завершить сеанс</button>
      </footer>
    </div>
  </div>
</template>

<style scoped>
.safety-number {
  font-size: 1.15rem;
  letter-spacing: .08em;
  white-space: pre-wrap;
  word-spacing: .4em;
}
</style>
