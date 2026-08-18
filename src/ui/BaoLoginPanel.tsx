/**
 * BaoLoginPanel — the unified BAO login GUI (React).
 *
 * One component, every app: extension (approval-popup) → passkey →
 * NIP-46 remote signer → collapsed key-paste (recovery only), plus
 * registration with FORCED backup (download-gated entry, paper path that
 * keeps the reminder pending). All logic lives in the headless
 * loginFlowMachine; this is the thin, themeable view.
 *
 * Theming: CSS variables with BAO newspaper defaults —
 *   --bao-accent, --bao-ink, --bao-muted, --bao-paper, --bao-rule,
 *   --bao-danger, --bao-success, --bao-font-mono, --bao-font-serif
 */
import React, { useEffect, useMemo, useState } from "react";
import { createLoginFlow, type LoginResult } from "../client/loginFlowMachine.ts";
import { isNip07Available } from "../client/nip07.ts";

export interface BaoLoginPanelProps {
  /** Called when login/register completes (with the method's session). */
  onDone: (result: LoginResult) => void;
  /** App-provided passkey login (e.g. bao-signer nativePasskeyAuth wrapper). */
  loginPasskey?: () => Promise<{ pubkey: string; session: unknown }>;
  /** Called with the downloaded backup file text at registration. */
  onBackupFile?: (text: string, filename: string) => void;
  className?: string;
}

const V = (name: string, fallback: string) => `var(--bao-${name}, ${fallback})`;

const btn = (kind: "primary" | "outline" | "disabled"): React.CSSProperties => ({
  fontFamily: V("font-mono", "ui-monospace, monospace"),
  width: "100%",
  padding: "10px 16px",
  fontSize: 11,
  fontWeight: 700,
  textTransform: "uppercase",
  letterSpacing: "0.15em",
  cursor: kind === "disabled" ? "not-allowed" : "pointer",
  opacity: kind === "disabled" ? 0.6 : 1,
  ...(kind === "primary"
    ? { color: V("on-accent", "#f7f3ec"), background: V("accent", "#b3442c"), border: `1px solid ${V("accent", "#b3442c")}` }
    : { color: V("ink", "#1a1a1a"), background: "transparent", border: `1px solid ${V("ink", "#1a1a1a")}` }),
});

export function BaoLoginPanel({ onDone, loginPasskey, onBackupFile, className }: BaoLoginPanelProps): React.ReactElement {
  const flow = useMemo(() => createLoginFlow(), []);

  // Extensions inject window.nostr ASYNCHRONOUSLY (often after first paint).
  // Checking once at mount hides the extension button forever — poll briefly
  // and re-check on window focus so the button appears without a reload.
  const [extAvail, setExtAvail] = useState(flow.nip07Available);
  useEffect(() => {
    if (extAvail) return;
    let tries = 0;
    const t = setInterval(() => {
      tries++;
      if (isNip07Available()) {
        setExtAvail(true);
        clearInterval(t);
      } else if (tries >= 20) {
        clearInterval(t); // give up after ~10s
      }
    }, 500);
    const onFocus = () => { if (isNip07Available()) setExtAvail(true); };
    window.addEventListener("focus", onFocus);
    return () => {
      clearInterval(t);
      window.removeEventListener("focus", onFocus);
    };
  }, [extAvail]);
  const [mode, setMode] = useState<"signin" | "register">("signin");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // collapsed sections
  const [showNip46, setShowNip46] = useState(false);
  const [showSeed, setShowSeed] = useState(false);
  const [bunkerUrl, setBunkerUrl] = useState("");
  const [seedInput, setSeedInput] = useState("");

  // register/backup flow
  const [pending, setPending] = useState<{ phrase: string; result: LoginResult } | null>(null);
  const [downloaded, setDownloaded] = useState(false);
  const [paper, setPaper] = useState(false);

  const run = async (fn: () => Promise<LoginResult>) => {
    setBusy(true);
    setError(null);
    try {
      onDone(await fn());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const downloadBackup = () => {
    if (!pending?.result.backupFileText) return;
    const filename = `bao-backup-${pending.result.pubkey.slice(0, 12)}.txt`;
    if (onBackupFile) {
      onBackupFile(pending.result.backupFileText, filename);
    } else {
      const blob = new Blob([pending.result.backupFileText], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10_000);
    }
    setDownloaded(true);
  };

  const register = async () => {
    setBusy(true);
    setError(null);
    try {
      setPending(await flow.registerSeed());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  /* ── backup view (after register) ── */
  if (pending) {
    return (
      <div className={className} style={{ maxWidth: 560, margin: "0 auto", padding: 16 }}>
        <h3 style={{ fontFamily: V("font-serif", "serif"), color: V("ink", "#1a1a1a"), fontSize: 20, fontWeight: 700, marginBottom: 8 }}>
          Back up your seed phrase
        </h3>
        <p style={{ fontSize: 12, lineHeight: 1.6, color: V("muted", "#6b6259"), marginBottom: 12 }}>
          These 24 words ARE your identity and wallet — in every BAO app, on any device.
          Save the file or write them down. Without a backup they cannot be recovered.
        </p>
        <div style={{ border: `1px solid ${V("rule", "#d8d2c8")}`, background: V("paper", "#f7f3ec"), padding: 12, marginBottom: 16, fontFamily: V("font-mono", "ui-monospace, monospace"), fontSize: 13, lineHeight: 2 }}>
          {pending.phrase.split(" ").map((w, i) => (
            <span key={i} style={{ display: "inline-block", marginRight: 10 }}>{i + 1}. {w}</span>
          ))}
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          <button type="button" onClick={downloadBackup} style={btn("primary")}>
            {downloaded ? "Backup file saved ✓ — download again" : "Save backup file (seed + nsec)"}
          </button>
          <button
            type="button"
            disabled={!downloaded}
            onClick={() => onDone({ ...pending.result, backupCompleted: true, phrase: pending.phrase })}
            style={downloaded ? btn("outline") : btn("disabled")}
          >
            Enter the app
          </button>
          {!downloaded && (
            <p style={{ textAlign: "center", fontSize: 10, color: V("muted", "#6b6259") }}>
              Save the file first — without it these words cannot be recovered.
            </p>
          )}
          <div style={{ borderTop: `1px solid ${V("rule", "#d8d2c8")}`, paddingTop: 8, marginTop: 4 }}>
            <label style={{ display: "flex", gap: 8, alignItems: "flex-start", fontSize: 11, color: V("muted", "#6b6259)" ) }}>
              <input type="checkbox" checked={paper} onChange={(e) => setPaper(e.target.checked)} style={{ marginTop: 2 }} />
              <span>
                Paper backup instead — I wrote down all 24 words and stored them safely.
                (The backup reminder stays until you also save the file or dismiss it in Settings.)
              </span>
            </label>
            <button
              type="button"
              disabled={!paper}
              onClick={() => onDone({ ...pending.result, backupCompleted: false, phrase: pending.phrase })}
              style={{ ...btn(paper ? "outline" : "disabled"), marginTop: 8, fontSize: 10 }}
            >
              Enter with paper backup
            </button>
          </div>
        </div>
      </div>
    );
  }

  /* ── choose view ── */
  return (
    <div className={className} style={{ maxWidth: 560, margin: "0 auto", padding: 16 }}>
      <div style={{ display: "flex", justifyContent: "center", gap: 12, marginBottom: 20 }}>
        {(["signin", "register"] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => setMode(m)}
            style={{
              fontFamily: V("font-mono", "ui-monospace, monospace"),
              padding: "6px 16px",
              fontSize: 11,
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "0.15em",
              cursor: "pointer",
              color: mode === m ? V("on-accent", "#f7f3ec") : V("ink", "#1a1a1a"),
              background: mode === m ? V("accent", "#b3442c") : "transparent",
              border: `1px solid ${V("ink", "#1a1a1a")}`,
            }}
          >
            {m === "signin" ? "Sign in" : "Register"}
          </button>
        ))}
      </div>

      {mode === "register" ? (
        <div style={{ border: `1px solid ${V("rule", "#d8d2c8")}`, background: V("paper", "#f7f3ec"), padding: 20 }}>
          <p style={{ fontSize: 12, lineHeight: 1.6, color: V("muted", "#6b6259"), marginBottom: 12 }}>
            Creates a new identity with a <b>24-word seed (256-bit entropy)</b>. The seed is the
            key to your wallet and identity everywhere — save it in a password manager or on
            paper. We never see it. After registering, prefer signing in with an extension or
            passkey on your other devices.
          </p>
          <button type="button" onClick={register} disabled={busy} style={btn("primary")}>
            {busy ? "Creating…" : "Create account — 24-word seed"}
          </button>
        </div>
      ) : (
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          {extAvail ? (
            <button
              type="button"
              onClick={() => void run(flow.loginNip07)}
              disabled={busy}
              style={btn("primary")}
            >
              Sign in with browser extension (recommended)
            </button>
          ) : (
            <div style={{ border: `1px solid ${V("rule", "#d8d2c8")}`, background: V("paper", "#f7f3ec"), padding: 12, textAlign: "center" }}>
              <p style={{ fontSize: 11, lineHeight: 1.6, color: V("muted", "#6b6259"), margin: 0 }}>
                <b style={{ color: V("ink", "#1a1a1a") }}>Recommended:</b> install a Nostr signer
                extension (Alby, nos2x, Amber) — it signs for you and your keys never touch
                this page. Reload after installing.
              </p>
            </div>
          )}

          {loginPasskey && flow.passkeyAvailable && (
            <button
              type="button"
              onClick={() => void run(async () => ({ method: "passkey" as const, ...(await loginPasskey()) }))}
              disabled={busy}
              style={btn("outline")}
            >
              Sign in with passkey
            </button>
          )}

          {/* NIP-46 remote signer */}
          <div style={{ border: `1px solid ${V("rule", "#d8d2c8")}`, background: V("paper", "#f7f3ec") }}>
            <button
              type="button"
              onClick={() => setShowNip46((v) => !v)}
              style={{ width: "100%", display: "flex", justifyContent: "space-between", padding: "8px 16px", fontSize: 10, textTransform: "uppercase", letterSpacing: "0.15em", fontFamily: V("font-mono", "ui-monospace, monospace"), color: V("muted", "#6b6259"), background: "transparent", border: "none", cursor: "pointer" }}
            >
              <span>Remote signer (NIP-46 · Amber / nsec.app)</span>
              <span>{showNip46 ? "▲" : "▼"}</span>
            </button>
            {showNip46 && (
              <div style={{ borderTop: `1px solid ${V("rule", "#d8d2c8")}`, padding: 16 }}>
                <p style={{ fontSize: 11, lineHeight: 1.6, color: V("muted", "#6b6259"), marginTop: 0 }}>
                  Keys stay on your phone or signer service — this page only receives signatures.
                  Paste your bunker:// connection URL from Amber or nsec.app.
                </p>
                <input
                  value={bunkerUrl}
                  onChange={(e) => setBunkerUrl(e.target.value)}
                  placeholder="bunker://…?relay=wss://…"
                  style={{ width: "100%", boxSizing: "border-box", border: `1px solid ${V("rule", "#d8d2c8")}`, background: "transparent", padding: "8px 10px", fontSize: 12, fontFamily: V("font-mono", "ui-monospace, monospace"), color: V("ink", "#1a1a1a"), marginBottom: 8 }}
                />
                <button
                  type="button"
                  disabled={busy || !flow.validateBunkerUrl(bunkerUrl).ok}
                  onClick={() => void run(() => flow.loginNip46(bunkerUrl))}
                  style={btn("primary")}
                >
                  Connect remote signer
                </button>
                {!flow.validateBunkerUrl(bunkerUrl).ok && (
                  <p style={{ marginTop: 6, textAlign: "center", fontSize: 10, color: V("muted", "#6b6259") }}>
                    Paste a valid bunker:// URL (with at least one wss:// relay) to enable this button.
                  </p>
                )}
              </div>
            )}
          </div>

          {/* Key-paste — recovery only, collapsed */}
          <div style={{ border: `1px solid ${V("rule", "#d8d2c8")}`, background: V("paper", "#f7f3ec") }}>
            <button
              type="button"
              onClick={() => setShowSeed((v) => !v)}
              style={{ width: "100%", display: "flex", justifyContent: "space-between", padding: "8px 16px", fontSize: 10, textTransform: "uppercase", letterSpacing: "0.15em", fontFamily: V("font-mono", "ui-monospace, monospace"), color: V("muted", "#6b6259"), background: "transparent", border: "none", cursor: "pointer" }}
            >
              <span>Paste key material — recovery only</span>
              <span>{showSeed ? "▲" : "▼"}</span>
            </button>
            {showSeed && (
              <div style={{ borderTop: `1px solid ${V("rule", "#d8d2c8")}`, padding: 16 }}>
                <p style={{ fontSize: 11, lineHeight: 1.6, color: V("danger", "#a03428"), marginTop: 0 }}>
                  <b>Not recommended in a browser.</b> Anyone (or any malware) that sees these
                  words controls your identity and funds. Prefer the extension — it exists so
                  you never have to do this.
                </p>
                <textarea
                  value={seedInput}
                  onChange={(e) => setSeedInput(e.target.value)}
                  rows={3}
                  placeholder="24 mnemonic words or nsec key"
                  autoComplete="off"
                  spellCheck={false}
                  style={{ width: "100%", boxSizing: "border-box", border: `1px solid ${V("rule", "#d8d2c8")}`, background: "transparent", padding: "8px 10px", fontSize: 12, fontFamily: V("font-mono", "ui-monospace, monospace"), color: V("ink", "#1a1a1a"), marginBottom: 8, resize: "vertical" }}
                />
                <button
                  type="button"
                  disabled={busy || !seedInput.trim()}
                  onClick={() => void run(() => flow.loginSeed(seedInput))}
                  style={btn("primary")}
                >
                  Sign in with seed / nsec
                </button>
                {!seedInput.trim() && (
                  <p style={{ marginTop: 6, textAlign: "center", fontSize: 10, color: V("muted", "#6b6259") }}>
                    Enter the 24 words or nsec key above to enable this button.
                  </p>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {busy && (
        <p style={{ marginTop: 16, textAlign: "center", fontSize: 11, color: V("muted", "#6b6259"), fontFamily: V("font-mono", "ui-monospace, monospace") }}>
          Working — check for an authenticator / extension popup…
        </p>
      )}
      {error && (
        <p style={{ marginTop: 16, textAlign: "center", fontSize: 12, color: V("danger", "#a03428") }}>
          {error}
        </p>
      )}
    </div>
  );
}
