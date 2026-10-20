import { platform } from '@tauri-apps/plugin-os';

let cached: boolean | null = null;

/** True on Android/iOS. Phones have no extra windows, window titles or drag&drop. */
export function isMobile(): boolean {
  if (cached === null) {
    try {
      const p = platform();
      cached = p === 'android' || p === 'ios';
    } catch {
      cached = /Android|iPhone|iPad/i.test(navigator.userAgent);
    }
  }
  return cached;
}
