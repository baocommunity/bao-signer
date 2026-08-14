# bao-signer — Security Model

This document describes the security properties, design decisions, and known
limitations of `bao-signer`. It also records the findings of the pre-release
review (2026-08-14) and how each was resolved.

## Cryptography

| Item | Construction |
|---|---|
| Nostr identity | secp256k1 / BIP-340 Schnorr (32-byte keys) |
| PRF → Nostr key | `sha256("bao:nostr:v1:" + hex(prfSeed))`, then scalar validation (re-derive with HMAC tweak if 0 or ≥ N) |
| Master key wrapping | AES-256-GCM, 12-byte random IV per wrap |
| Passkey → wrapping key | HKDF-SHA256(PRF seed, salt=`bao:native_passkey:salt:v1`, info=`master`) |
| Per-community keys | HMAC-SHA256(master, `bao/<id>/<index>`), scalar-validated |
| Relay backup key | HMAC-SHA256(serverSecret, credentialId), truncated to 16 bytes |
| Server nsec storage | SHA-256(nsec_hex) only — plaintext shown once, never stored |

All keys are 256-bit. secp256k1 keys are 32 bytes by definition; "stronger
encryption" here means better key *hygiene* (wrapping, domain separation,
scalar validation, no plaintext caching), not longer keys.

## Passkey policy

- `userVerification: "required"` everywhere — biometric or PIN, never tap-only.
- `residentKey: "required"` at account registration.
- `attestation: "none"` — we do not need hardware provenance, and skipping it
  is better for privacy.
- WebAuthn signature counters: regressions are logged and tolerated (synced
  passkeys legitimately reset counters), but the stored counter is **never
  decreased**.
- Challenges are single-use with a 5-minute TTL.

## The anonymous-PRF-registration policy (important)

A WebAuthn attestation proves control of the **new credential**. It does NOT
prove control of a **caller-supplied Nostr pubkey**. If anonymous registration
accepted `pubkey` from the client, anyone could attach *their* passkey to
*your* public identity and receive sessions for it.

Therefore `POST /auth/passkey/register` rejects any request carrying a
client-supplied pubkey with `PRF_ACCOUNT_LINK_REQUIRES_AUTH`. PRF-derived
identities are bound through the authenticated link flow
(`POST /auth/link/passkey/*`), where the challenge is bound to the current
session pubkey.

## Threat model notes

- **XSS is out of scope for localStorage-based modes.** The wrapped master key
  and encrypted nsec in localStorage are ciphertext, but an XSS payload can
  call the unlock functions while the user is present. This is inherent to
  browser wallets; CSP and diligent dependency hygiene are the mitigations.
- **In-memory challenge/nsec/session stores are single-process.** Multi-replica
  deployments must back them with a shared store (Redis/Postgres) or sticky
  sessions.
- **Server-generated (non-PRF) accounts see the nsec once server-side.** This
  is a deliberate usability tradeoff; PRF accounts are fully self-custodial
  and the server never sees key material.
- **`__bao_test_prf_available`** (`window.__bao_test_prf_available`) is a test
  hook for E2E suites. It only fakes *availability detection* in the UI; it
  cannot fabricate PRF output or keys.

## Pre-release review findings (2026-08-14) and resolutions

| # | Finding | Severity | Resolution |
|---|---|---|---|
| H1 | Anonymous PRF registration allowed claiming any existing pubkey (account takeover) | High | Fixed in bao.markets `main` before extraction (reject + authenticated link flow); policy carried into this repo |
| M1 | `privateKeyHex` field actually contained the raw PRF seed, not the Nostr key | Medium | Renamed to `prfSeedHex` with explicit docs |
| M2 | Relay backup key had a deterministic fallback derivable from public credentialId | Medium | Fail-closed: HMAC secret is required, no fallback |
| M3 | Non-PRF mode shows nsec server-side once | Medium | Documented tradeoff (this file) |
| L1 | In-memory stores single-process only | Low | Documented; storage interface allows shared backends |
| L2 | E2E test hook in production code | Low | Documented above; availability-only, cannot forge keys |
| L3 | Counter regression tolerated | Low | Correct for synced passkeys; stored counter never decreases |
| — | PRF-derived Nostr key lacked scalar validation | Info | `ensureValidSecp256k1Scalar` applied |

## Reporting

Open a private security advisory on GitHub, or contact the maintainers via
the bao.community channels. Do not file public issues for vulnerabilities.
