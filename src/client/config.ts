/**
 * bao-signer client configuration.
 *
 * The client never assumes a hardcoded API origin. Configure once at app
 * startup, or pass `apiBaseUrl` per call.
 *
 * ```ts
 * import { configureBaoSignerClient } from "bao-signer/client";
 * configureBaoSignerClient({ apiBaseUrl: "https://api.example.com/bao-api" });
 * ```
 */

export interface BaoSignerClientConfig {
  /**
   * Base URL of the bao-signer server API, WITHOUT trailing slash and WITHOUT
   * the `/v1` prefix. The client appends `/v1/auth/passkey/...` itself.
   * Example: "https://api.example.com/bao-api"
   */
  apiBaseUrl: string;
}

let clientConfig: BaoSignerClientConfig | null = null;

export function configureBaoSignerClient(config: BaoSignerClientConfig): void {
  if (!config.apiBaseUrl || typeof config.apiBaseUrl !== "string") {
    throw new Error("configureBaoSignerClient: apiBaseUrl is required");
  }
  clientConfig = { apiBaseUrl: config.apiBaseUrl.replace(/\/+$/, "") };
}

/**
 * Resolve the API base URL. Per-call override wins; otherwise the configured
 * value. Fails closed when neither is set — we never fall back to a hardcoded
 * origin.
 */
export function getSignerApiBase(override?: string): string {
  const base = override ?? clientConfig?.apiBaseUrl;
  if (!base) {
    throw new Error(
      "bao-signer: API base URL not configured. Call configureBaoSignerClient({ apiBaseUrl }) first, " +
        "or pass { apiBaseUrl } to the register/login functions.",
    );
  }
  return base.replace(/\/+$/, "");
}

/** Test hook: reset configuration between tests. */
export function __resetBaoSignerClientConfig(): void {
  clientConfig = null;
}
