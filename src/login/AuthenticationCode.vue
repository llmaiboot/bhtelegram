<script setup lang="ts">
import { invoke } from '@tauri-apps/api/core';
import { computed, onBeforeUnmount, ref, watch } from 'vue';

export type LoginCodeInfo = {
  phone_number: string;
  delivery: string;
  next_delivery: string | null;
  length: number;
  timeout: number;
};

const props = defineProps<{ info: LoginCodeInfo | null }>();

const code = ref('');
const error = ref('');
const disableNextBtn = ref(false);
const resending = ref(false);
const secondsLeft = ref(0);
let timer: ReturnType<typeof setInterval> | null = null;

const deliveryLabels: Record<string, string> = {
  telegram_message: 'in the Telegram app on your other device (chat "Telegram", blue tick). Not by SMS!',
  sms: 'by SMS',
  call: 'by a phone call (the code will be dictated)',
  flash_call: 'by a missed call (the code is the last digits of the caller number)',
  missed_call: 'by a missed call (the code is the last digits of the caller number)',
  fragment: 'on fragment.com (anonymous number)',
  firebase: 'by SMS',
};

const deliveryText = computed(() => {
  const d = props.info?.delivery;
  return d ? (deliveryLabels[d] ?? d) : '';
});

const nextText = computed(() => {
  const n = props.info?.next_delivery;
  if (!n) {
    return '';
  }
  if (n === 'sms' || n === 'firebase') return 'Send by SMS';
  if (n === 'call') return 'Call me';
  if (n === 'flash_call' || n === 'missed_call') return 'Missed call';
  return 'Resend code';
});

function startTimer(seconds: number) {
  if (timer) {
    clearInterval(timer);
  }
  secondsLeft.value = Math.max(0, seconds);
  timer = setInterval(() => {
    if (secondsLeft.value > 0) {
      secondsLeft.value -= 1;
    } else if (timer) {
      clearInterval(timer);
      timer = null;
    }
  }, 1000);
}

watch(() => props.info, (info) => {
  if (info) {
    startTimer(info.timeout);
    resending.value = false;
  }
}, { immediate: true });

onBeforeUnmount(() => {
  if (timer) {
    clearInterval(timer);
  }
});

async function next() {
  error.value = '';
  disableNextBtn.value = true;
  try {
    await invoke('set_authentication_code', { code: code.value.trim() });
  } catch (err) {
    disableNextBtn.value = false;
    error.value = err as string;
  }
}

async function resend() {
  error.value = '';
  resending.value = true;
  try {
    // TDLib answers with a new authorizationStateWaitCode -> props.info updates
    await invoke('resend_authentication_code');
  } catch (err) {
    resending.value = false;
    error.value = err as string;
  }
}

async function useQr() {
  error.value = '';
  try {
    await invoke('request_qr_code_authentication');
  } catch (err) {
    error.value = err as string;
  }
}
</script>

<template>
  <form @submit.prevent="next" class="m-5">
    <div class="notification is-info is-light" v-if="info">
      Code sent to <strong>{{ info.phone_number }}</strong> {{ deliveryText }}
      <span v-if="info.length">({{ info.length }} digits)</span>
    </div>
    <div class="field mt-3">
      <label class="label mb-0" for="code">Authentication code</label>
      <div class="control">
        <input class="input" type="text" id="code" v-model="code" autocomplete="one-time-code" inputmode="numeric" />
      </div>
    </div>
    <div class="message is-danger mt-3" v-if="error">
      <div class="message-body">
        {{ error }}
      </div>
    </div>
    <div class="field is-grouped is-grouped-centered mt-3">
      <div class="control">
        <button class="button is-link" type="submit" :disabled="disableNextBtn">Next</button>
      </div>
    </div>
    <div class="has-text-centered mt-4">
      <button v-if="nextText" class="button is-small" type="button" @click="resend"
        :disabled="resending || secondsLeft > 0">
        {{ nextText }}<span v-if="secondsLeft > 0">&nbsp;({{ secondsLeft }}s)</span>
      </button>
      <p v-else class="help">No other delivery method available for this number.</p>
      <button class="button is-small is-text ml-2" type="button" @click="useQr">Log in with QR code instead</button>
    </div>
  </form>
</template>
