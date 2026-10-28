import { invoke } from '@tauri-apps/api/core';

export interface AtlasStatus {
  signedIn: boolean;
  sessionId: string | null;
}

/** Open the hosted sign-in in the system browser and resolve when the person has finished. */
export const signIn = (): Promise<AtlasStatus> => invoke('plugin:atlas|sign_in');

/** A fresh session token for calls to your API (refreshed when it is about to expire), or null when signed out. */
export const getToken = (): Promise<string | null> => invoke('plugin:atlas|get_token');

export const status = (): Promise<AtlasStatus> => invoke('plugin:atlas|status');

export const signOut = (): Promise<void> => invoke('plugin:atlas|sign_out');
