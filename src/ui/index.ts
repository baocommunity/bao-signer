/**
 * bao-signer/ui — the unified BAO login GUI (React).
 * Mount <BaoLoginPanel onDone={...} /> and every app shares the same
 * login UX: extension popup / passkey / NIP-46 / collapsed seed recovery /
 * forced-backup registration.
 */
export { BaoLoginPanel, type BaoLoginPanelProps } from "./BaoLoginPanel.tsx";
