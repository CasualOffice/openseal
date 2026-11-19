// Types of the OpenSeal API client (slice 8, VS-08E). The per-operation methods are in
// operations.d.ts, generated from api/openapi.yaml by tools/build-sdks.py.
import type { Operations } from "./operations.js";

export { OPERATIONS } from "./operations.js";
export type { Operations, Params } from "./operations.js";

export declare class OpenSealError extends Error {
  status: number;
  /** The stable code (docs/20), e.g. `CS-AUTH-0006`; for a webhook refusal `webhook_signature`. */
  code: string;
  title: string;
  detail: string;
  requestId: string | null;
  errors: { pointer: string; code: string }[];
  /** An OAuth token error's `error` (`invalid_grant`, ...). */
  oauthError: string | null;
}

export interface OpenSealOptions {
  baseUrl: string;
  /** A personal API key, `osk_…`. */
  apiKey?: string | null;
  /** An OAuth access token. */
  accessToken?: string | null;
  fetch?: typeof fetch;
  userAgent?: string | null;
}

export interface TokenResponse {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  scope: string;
  refresh_token?: string;
}

export declare class OpenSeal {
  constructor(options: OpenSealOptions);
  authorizationUrl(o: { clientId: string; redirectUri: string; scope: string | string[]; state?: string | null }): Promise<{ url: string; verifier: string; state: string }>;
  token(o: { clientId?: string | null; clientSecret?: string | null; grant_type?: string; [k: string]: unknown }): Promise<TokenResponse>;
}
export interface OpenSeal extends Operations {}

export declare function verifyWebhook(
  secret: string,
  headers: Headers | Record<string, string>,
  body: string | ArrayBuffer | Uint8Array,
  options?: { toleranceSeconds?: number; now?: number },
): Promise<{ id: string; type: string; created_at: string; account_id: string; data: Record<string, unknown> }>;
