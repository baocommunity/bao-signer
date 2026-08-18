/**
 * loginFlowMachine — the unified login UX as a pure, framework-free state
 * machine. This is the brain of BaoLoginPanel (React view) and is fully
 * unit-testable without a DOM.
 *
 * Encodes the BAO key-handling philosophy:
 *  - Extension (NIP-07) is the recommended daily path — keys never touch
 *    the page; the machine's connect call MUST be invoked synchronously
 *    from the click handler (gesture preservation for the approval popup).
 *  - Passkey second (keys live in the authenticator).
 *  - NIP-46 remote signer for phones (bunker://).
 *  - Key-paste (seed/nsec) is collapsed recovery-only.
 *  - Registration FORCES a real backup: 'enter' stays locked until the
 *    backup file was downloaded; a deliberate paper path keeps the
 *    reminder pending.
 */

import { isNip07Available, connectNip07Signer } from "./nip07.ts";
import { connectNip46Signer, parseBunkerUrl } from "./nip46.ts";
import { newSeedPhrase, validateSeedPhrase, createSeedIdentitySigner } from "./seedIdentity.ts";
import { nip19 } from "nostr-tools";

export type LoginMethod = "nip07" | "passkey" | "nip46" | "seed";

export type FlowState =
  | { step: "choose" }
  | { step: "busy"; method: LoginMethod | "register" }
  | { step: "backup"; phrase: string; pubkey: string }
  | { step: "error"; message: string }
  | { step: "done"; method: LoginMethod; pubkey: string };

export interface LoginResult {
  method: LoginMethod;
  pubkey: string;
  /** Method-specific signer session (shape varies; callers cast). */
  session: unknown;
  /** Present only for seed-phrase registration — the backup file text. */
  backupFileText?: string;
  /** Registration: true when the user downloaded the backup file (false =
   * paper path — the app should keep the backup reminder pending). */
  backupCompleted?: boolean;
  /** Registration: the 24-word phrase (handle with care, clear after use). */
  phrase?: string;
}

export interface FlowDeps {
  /** Passkey login (bao-signer nativePasskeyAuth or app-provided). */
  loginPasskey?: () => Promise<{ pubkey: string; session: unknown }>;
  /** Optional timeout for the extension prompt. */
  nip07TimeoutMs?: number;
}

export interface Machine {
  state: FlowState;
  nip07Available: boolean;
  passkeyAvailable: boolean;
  loginNip07: () => Promise<LoginResult>;
  loginNip46: (bunkerUrl: string) => Promise<LoginResult>;
  loginSeed: (input: string) => Promise<LoginResult>;
  registerSeed: () => Promise<{ phrase: string; result: LoginResult }>;
  /** Build the backup file contents for a registered identity. */
  buildBackupFileText: (phrase: string, pubkey: string, nsec: string) => string;
  /** Validate a bunker URL without connecting. */
  validateBunkerUrl: (url: string) => { ok: boolean; error?: string };
}

export function createLoginFlow(deps: FlowDeps = {}): Machine {
  const state: FlowState = { step: "choose" };

  const machine: Machine = {
    state,
    nip07Available: typeof window !== "undefined" && isNip07Available(),
    passkeyAvailable:
      typeof window !== "undefined" && typeof (window as { PublicKeyCredential?: unknown }).PublicKeyCredential !== "undefined",

    async loginNip07(): Promise<LoginResult> {
      // NOTE: invoke synchronously from a click handler (gesture → popup).
      const session = await connectNip07Signer({ timeoutMs: deps.nip07TimeoutMs });
      return { method: "nip07", pubkey: session.pubkey, session };
    },

    async loginNip46(bunkerUrl: string): Promise<LoginResult> {
      const session = await connectNip46Signer(bunkerUrl.trim());
      return { method: "nip46", pubkey: session.pubkey, session };
    },

    async loginSeed(input: string): Promise<LoginResult> {
      const trimmed = input.trim();
      let identity;
      if (trimmed.startsWith("nsec1")) {
        const decoded = nip19.decode(trimmed);
        if (decoded.type !== "nsec") throw new Error("Invalid nsec key");
        const { createNip44IdentitySigner } = await import("./signer.ts");
        identity = createNip44IdentitySigner(decoded.data as Uint8Array);
      } else {
        if (!validateSeedPhrase(trimmed)) {
          throw new Error("Invalid seed phrase — enter the 24 mnemonic words or the nsec key");
        }
        identity = createSeedIdentitySigner(trimmed);
      }
      return { method: "seed", pubkey: identity.pubkey, session: identity };
    },

    async registerSeed(): Promise<{ phrase: string; result: LoginResult }> {
      const phrase = newSeedPhrase(256);
      const identity = createSeedIdentitySigner(phrase);
      const backupFileText = machine.buildBackupFileText(phrase, identity.pubkey, identity.nsec);
      return {
        phrase,
        result: { method: "seed", pubkey: identity.pubkey, session: identity, backupFileText },
      };
    },

    buildBackupFileText(phrase: string, pubkey: string, nsec: string): string {
      return [
        "₿AO wallet backup",
        `created: ${new Date().toISOString()}`,
        `identity pubkey (hex): ${pubkey}`,
        "== DO NOT SHARE: anyone with this file controls the identity and funds ==",
        `nsec: ${nsec}`,
        "",
        "BIP-39 seed (24 words):",
        phrase,
        "",
      ].join("\n");
    },

    validateBunkerUrl(url: string): { ok: boolean; error?: string } {
      const r = parseBunkerUrl(url);
      return r.valid ? { ok: true } : { ok: false, error: r.error };
    },
  };

  return machine;
}
