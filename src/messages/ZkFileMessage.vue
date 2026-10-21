<script setup lang="ts">
import { onBeforeUnmount, ref } from 'vue';
import { convertFileSrc } from '@tauri-apps/api/core';
import { openPath } from '@tauri-apps/plugin-opener';
import { save } from '@tauri-apps/plugin-dialog';
import { MessageWithStatus, MessageZk, ZkOpenedFile } from '../model';
import { zkOpenFile } from '../services/zk';
import { saveFile } from '../services/files';
import { FontAwesomeIcon } from '@fortawesome/vue-fontawesome';
import { faFile, faMicrophone, faDownload } from '@fortawesome/free-solid-svg-icons';

const props = defineProps<{
  message: MessageWithStatus,
  content: MessageZk
}>();

const opened = ref<ZkOpenedFile | null>(null);
const loading = ref(false);
const error = ref('');

const isImage = () => opened.value?.mime.startsWith('image/') ?? false;
const isAudio = () => props.content.voice || (opened.value?.mime.startsWith('audio/') ?? false);
const src = () => (opened.value ? convertFileSrc(opened.value.path) : '');

async function open() {
  error.value = '';
  loading.value = true;
  try {
    opened.value = await zkOpenFile(props.message.chat_id, props.message.id);
  } catch (err) {
    error.value = err as string;
  } finally {
    loading.value = false;
  }
}

async function openExternal() {
  if (opened.value) {
    await openPath(`file://${opened.value.path}`);
  }
}

async function saveAs() {
  if (!opened.value) return;
  const target = await save({ defaultPath: opened.value.name });
  if (target) {
    await saveFile(opened.value.path, target);
  }
}

// Decrypted copy is wiped on lock/exit; drop the reference with the bubble.
onBeforeUnmount(() => {
  opened.value = null;
});
</script>

<template>
  <div>
    <button v-if="!opened" type="button" class="button is-small" :class="{ 'is-loading': loading }" @click="open">
      <FontAwesomeIcon :icon="content.voice ? faMicrophone : faFile" class="mr-2" />
      {{ content.voice ? 'Голосовое — расшифровать' : 'Файл — расшифровать' }}
    </button>
    <template v-else>
      <img v-if="isImage()" :src="src()" class="zk-image" :alt="opened.name" />
      <audio v-else-if="isAudio()" :src="src()" controls preload="metadata" class="zk-audio"></audio>
      <div class="is-flex is-align-items-center mt-1" style="gap: .5rem">
        <a href="#" @click.prevent="openExternal" class="zk-name">{{ opened.name }}</a>
        <button type="button" class="button is-small is-text" @click="saveAs" aria-label="Save">
          <FontAwesomeIcon :icon="faDownload" />
        </button>
      </div>
      <p v-if="opened.caption" class="mt-1 zk-caption">{{ opened.caption }}</p>
    </template>
    <p v-if="error" class="has-text-danger is-size-7 mt-1">{{ error }}</p>
  </div>
</template>

<style scoped>
.zk-image {
  max-width: 100%;
  max-height: 60vh;
  border-radius: 4px;
}
.zk-audio {
  width: 100%;
  max-width: 320px;
}
.zk-name {
  word-break: break-all;
}
.zk-caption {
  white-space: pre-wrap;
}
</style>
