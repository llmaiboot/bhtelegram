import { invoke } from '@tauri-apps/api/core';
import { Message } from '../model';

export type ZkStatus = {
  state: 'none' | 'active';
  safety_number: string | null;
  verified: boolean;
  peer_changed: boolean;
  has_history: boolean;
};

export async function zkStatus(chatId: number): Promise<ZkStatus> {
  return await invoke<ZkStatus>('zk_status', { chatId });
}

export async function zkStartSession(chatId: number): Promise<Message> {
  return await invoke<Message>('zk_start_session', { chatId });
}

export async function zkAcceptInvite(chatId: number, messageId: number): Promise<Message> {
  return await invoke<Message>('zk_accept_invite', { chatId, messageId });
}

export async function zkSendText(chatId: number, text: string): Promise<Message[]> {
  return await invoke<Message[]>('zk_send_text', { chatId, text });
}

export async function zkEndSession(chatId: number): Promise<Message> {
  return await invoke<Message>('zk_end_session', { chatId });
}

export async function zkSetVerified(chatId: number, verified: boolean): Promise<void> {
  await invoke('zk_set_verified', { chatId, verified });
}

export async function lockApp(): Promise<void> {
  await invoke('lock_app');
}
