<script setup lang="ts">
import { nextTick, onMounted } from 'vue';
import { MessagePgpHidden, MessageWithStatus } from '../model';
import { store } from '../store';
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome';
import { faEyeSlash } from '@fortawesome/free-solid-svg-icons';

const props = defineProps<{
  message: MessageWithStatus,
  content: MessagePgpHidden
}>();

onMounted(async () => {
  await nextTick(() => {
    store.messageLoaded(props.message.id);
  });
});
</script>

<template>
  <p class="is-italic has-text-grey pgp-hidden">
    <FontAwesomeIcon :icon="faEyeSlash" class="mr-1" />
    {{ props.content.is_file ? 'Encrypted file' : 'Encrypted message' }} — hidden
  </p>
</template>
