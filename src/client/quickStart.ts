/**
 * Quick Start — one-click guest onboarding (Nostr UX pattern: value before commitment).
 *
 * Flow:
 * 1. User clicks "Quick Start"
 * 2. Keys generated silently, stored encrypted (see keyStorage.ts)
 * 3. User can immediately use the app
 * 4. After first valuable action, show backup reminder
 * 5. User backs up their nsec at their own pace (or upgrades to a passkey)
 *
 * The nsec is never stored in plaintext and never returned by account
 * creation — use `getQuickStartNsec()` for the one-time backup display.
 */

import {
  generateKeyPair,
  encodeNsec,
  encodeNpub,
  storeKeyPair,
  loadStoredPrivateKey,
  keyStorageKey,
} from "./keyStorage.ts";

// Evaluated at call time so configureKeyStorage({ storagePrefix }) applies
// even after import. Default-prefix names are unchanged from the historical
// hardcoded ones.
const STORAGE_KEYS = {
  get QUICK_START_ACCOUNT() { return keyStorageKey("quick_start_account"); },
  get NEEDS_BACKUP() { return keyStorageKey("needs_backup"); },
  get BACKUP_REMINDER_DISMISSED() { return keyStorageKey("backup_reminder_dismissed"); },
  get FIRST_ACTION_COMPLETED() { return keyStorageKey("first_action_completed"); },
  get BACKUP_COMPLETED() { return keyStorageKey("backup_completed"); },
} as const;

export interface QuickStartAccount {
  publicKey: string;
  npub: string;
  createdAt: number;
}

function isValidQuickStartAccount(value: unknown): value is QuickStartAccount {
  if (value === null || typeof value !== "object") return false;
  const obj = value as Record<string, unknown>;
  return (
    typeof obj.publicKey === "string" &&
    typeof obj.npub === "string" &&
    typeof obj.createdAt === "number"
  );
}

/**
 * Create a new account instantly with one click.
 * Keys are stored encrypted; the account record never contains the nsec.
 */
export async function createQuickStartAccount(): Promise<QuickStartAccount> {
  const keyPair = generateKeyPair();
  const npub = encodeNpub(keyPair.publicKey);

  // Await so callers can safely read from storage without racing the write.
  await storeKeyPair(keyPair);

  const account: QuickStartAccount = {
    publicKey: keyPair.publicKey,
    npub,
    // nsec intentionally omitted — retrieve via getQuickStartNsec()
    createdAt: Date.now(),
  };

  // localStorage can fail in private-browsing mode; the account is still
  // valid for the current session.
  try {
    localStorage.removeItem(STORAGE_KEYS.BACKUP_COMPLETED);
    localStorage.removeItem(STORAGE_KEYS.BACKUP_REMINDER_DISMISSED);
    localStorage.setItem(STORAGE_KEYS.QUICK_START_ACCOUNT, JSON.stringify(account));
    localStorage.setItem(STORAGE_KEYS.NEEDS_BACKUP, "true");
    localStorage.setItem(STORAGE_KEYS.FIRST_ACTION_COMPLETED, "true");
  } catch (err) {
    console.warn(
      "[quickStart] localStorage unavailable — session will not persist:",
      err instanceof Error ? err.message : String(err),
    );
  }

  return account;
}

/** Check if a quick start account needs backup (24h re-show after dismiss). */
export function needsBackupReminder(): boolean {
  try {
    const needsBackup = localStorage.getItem(STORAGE_KEYS.NEEDS_BACKUP) === "true";
    const backupCompleted = localStorage.getItem(STORAGE_KEYS.BACKUP_COMPLETED) === "true";
    const dismissed = localStorage.getItem(STORAGE_KEYS.BACKUP_REMINDER_DISMISSED);

    if (!needsBackup || backupCompleted) return false;

    if (dismissed) {
      const dismissedAt = parseInt(dismissed, 10);
      if (!Number.isFinite(dismissedAt)) return false;
      const hoursSinceDismiss = (Date.now() - dismissedAt) / (1000 * 60 * 60);
      if (hoursSinceDismiss < 24) return false;
    }

    return true;
  } catch {
    return false;
  }
}

/** Whether to show the backup reminder (after first valuable action). */
export function shouldShowBackupReminder(): boolean {
  try {
    const firstActionCompleted =
      localStorage.getItem(STORAGE_KEYS.FIRST_ACTION_COMPLETED) === "true";
    return firstActionCompleted && needsBackupReminder();
  } catch {
    return false;
  }
}

/** Mark the first valuable action (post, vote, trade…). */
export function markFirstActionCompleted(): void {
  localStorage.setItem(STORAGE_KEYS.FIRST_ACTION_COMPLETED, "true");
  window.dispatchEvent(new CustomEvent("baoSigner.firstActionCompleted"));
}

/** Dismiss the backup reminder (re-shows after 24h). */
export function dismissBackupReminder(): void {
  localStorage.setItem(STORAGE_KEYS.BACKUP_REMINDER_DISMISSED, Date.now().toString());
  window.dispatchEvent(new CustomEvent("baoSigner.backupReminderDismissed"));
}

/** Mark backup completed (reminder never shows again). */
export function markBackupCompleted(): void {
  localStorage.setItem(STORAGE_KEYS.BACKUP_COMPLETED, "true");
  localStorage.removeItem(STORAGE_KEYS.NEEDS_BACKUP);
  window.dispatchEvent(new CustomEvent("baoSigner.backupCompleted"));
}

/**
 * Get the account's nsec for the one-time backup display.
 * Reads from the encrypted store; returns null on any error.
 */
export async function getQuickStartNsec(): Promise<string | null> {
  const hex = await loadStoredPrivateKey();
  if (!hex) return null;
  return encodeNsec(hex);
}

/** Get the quick start account record (no key material). */
export function getQuickStartAccount(): QuickStartAccount | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEYS.QUICK_START_ACCOUNT);
    if (raw) {
      const parsed: unknown = JSON.parse(raw);
      if (isValidQuickStartAccount(parsed)) return parsed;
    }
  } catch {
    /* ignore */
  }
  return null;
}

export function isQuickStartAccount(): boolean {
  return !!getQuickStartAccount();
}

/** Clear quick start data (on logout). */
export function clearQuickStartData(): void {
  Object.values(STORAGE_KEYS).forEach((key) => {
    try {
      localStorage.removeItem(key);
    } catch {
      /* ignore */
    }
  });
}

export default {
  createQuickStartAccount,
  needsBackupReminder,
  shouldShowBackupReminder,
  markFirstActionCompleted,
  dismissBackupReminder,
  markBackupCompleted,
  getQuickStartNsec,
  getQuickStartAccount,
  isQuickStartAccount,
  clearQuickStartData,
};
