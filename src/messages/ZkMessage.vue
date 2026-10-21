<script setup lang="ts">
import { nextTick, onMounted, ref } from 'vue';
import { MessageWithStatus, MessageZk } from '../model';
import { store } from '../store';
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome';
import { faShieldHalved, faEyeSlash, faTriangleExclamation, faLock } from '@fortawesome/free-solid-svg-icons';
import { zkAcceptInvite, zkStatus } from '../services/zk';
import ZkFileMessage from './ZkFileMessage.vue';

const props = defineProps<{
  message: MessageWithStatus,
  content: MessageZk
}>();

const busy = ref(false);
const error = ref('');

async function accept() {
  error.value = '';
  if (store.selectedZk?.state === 'active'
    && !confirm('Защищённый сеанс уже идёт. Принять новое приглашение и заменить ключи?')) {
    return;
  }
  busy.value = true;
  try {
    await zkAcceptInvite(props.message.chat_id, props.message.id);
    store.selectedZk = await zkStatus(props.message.chat_id);
  } catch (err) {
    error.value = err as string;
  } finally {
    busy.value = false;
  }
}

onMounted(async () => {
  // A session just started or ended: refresh the header shield.
  if ((props.content.kind === 'started' || props.content.kind === 'ended')
    && store.selectedChat?.id === props.message.chat_id) {
    try {
      store.selectedZk = await zkStatus(props.message.chat_id);
    } catch { /* locked */ }
  }
  await nextTick(() => {
    store.messageLoaded(props.message.id);
  });
});
</script>

<template>
  <div class="zk-message">
    <template v-if="content.kind === 'text'">
      <p class="zk-text">{{ content.text }}</p>
    </template>
    <ZkFileMessage v-else-if="content.kind === 'file'" :message="message" :content="content" />
    <p v-else-if="content.kind === 'hidden'" class="is-italic has-text-grey">
      <FontAwesomeIcon :icon="faEyeSlash" class="mr-1" />
      {{ content.voice ? 'Защищённое голосовое' : content.is_file ? 'Защищённый файл' : 'Защищённое сообщение' }} — скрыто
    </p>
    <div v-else-if="content.kind === 'invite'">
      <p>
        <FontAwesomeIcon :icon="faShieldHalved" class="mr-1" />
        <template v-if="content.outgoing">Вы пригласили в защищённый чат. Ждём ответа.</template>
        <template v-else>Приглашение в защищённый чат (Double Ratchet).</template>
      </p>
      <button v-if="!content.outgoing && message.sender_user_id !== store.myId" type="button" class="button is-small is-success mt-2" :disabled="busy"
        @click="accept">Принять</button>
      <p v-if="error" class="has-text-danger is-size-7 mt-1">{{ error }}</p>
    </div>
    <p v-else-if="content.kind === 'invite_accepted'" class="has-text-grey">
      <FontAwesomeIcon :icon="faShieldHalved" class="mr-1" /> Приглашение принято
    </p>
    <p v-else-if="content.kind === 'started'" class="has-text-success">
      <FontAwesomeIcon :icon="faShieldHalved" class="mr-1" /> Защищённый сеанс установлен
    </p>
    <p v-else-if="content.kind === 'ended'" class="has-text-grey">
      <FontAwesomeIcon :icon="faShieldHalved" class="mr-1" /> Защищённый сеанс завершён
    </p>
    <p v-else-if="content.kind === 'locked'" class="is-italic has-text-grey">
      <FontAwesomeIcon :icon="faLock" class="mr-1" /> Приложение заблокировано
    </p>
    <p v-else class="is-italic has-text-grey">
      <FontAwesomeIcon :icon="faTriangleExclamation" class="mr-1" />
      Не удалось расшифровать на этом устройстве
    </p>
  </div>
</template>

<style scoped>
.zk-text {
  white-space: pre-wrap;
  word-break: break-word;
}
</style>
