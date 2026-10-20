<script setup lang="ts">
import { nextTick, ref, watch } from 'vue';
import QRCode from 'qrcode';

const props = defineProps<{ link: string }>();
// Drawn on a canvas: the app CSP (img-src 'self' asset:) blocks data: images.
const canvas = ref<HTMLCanvasElement | null>(null);
const error = ref('');

// The tg://login link is refreshed by TDLib every ~30s, redraw each time.
watch(() => props.link, async (link) => {
  if (!link) {
    return;
  }
  try {
    await nextTick();
    if (canvas.value) {
      await QRCode.toCanvas(canvas.value, link, { width: 260, margin: 2 });
    }
    error.value = '';
  } catch (err) {
    error.value = String(err);
  }
}, { immediate: true });
</script>

<template>
  <div class="m-5 has-text-centered">
    <p class="title is-5">Log in with QR code</p>
    <div class="is-inline-block" style="background: #fff; padding: 8px; line-height: 0;">
      <canvas ref="canvas" aria-label="Telegram login QR code"></canvas>
    </div>
    <div class="message is-danger mt-3" v-if="error">
      <div class="message-body">{{ error }}</div>
    </div>
    <div class="content has-text-left mt-4" style="max-width: 420px; margin: auto;">
      <ol>
        <li>Open Telegram on your phone</li>
        <li>Go to <strong>Settings → Devices → Link Desktop Device</strong></li>
        <li>Scan this code</li>
      </ol>
      <p class="help">The code refreshes automatically. If your account has a cloud password, you will be asked for it next.</p>
    </div>
  </div>
</template>
