import crypto from 'crypto';
import config from '@/config/index.js';
import { logger } from '@/utils/logger.js';
import { AuthenticationError } from '@/middleware/errorHandler.js';

/**
 * Generic OpenID Connect (OIDC) service for developer-portal login.
 *
 * Implements the authorization-code flow against any compliant provider
 * (Keycloak, Authentik, Auth0, Okta, Azure AD, Dex, …) using only
 * node:crypto — ID-token signatures are verified against the provider's
 * JWKS, and issuer / audience / expiry / nonce claims are all checked.
 * No tokens or codes are persisted; state + PKCE verifier travel inside
 * the HMAC-signed state parameter.
 */

export interface OidcIdentity {
  subject: string;
  email: string;
  name?: string;
  picture?: string;
}

interface OidcDiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  userinfo_endpoint?: string;
  jwks_uri: string;
}

interface OidcTokenResponse {
  id_token?: string;
  access_token?: string;
  token_type?: string;
  error?: string;
  error_description?: string;
}

interface OidcStatePayload {
  nonce: string;
  verifier: string;
  iat: number;
}

const OIDC_STATE_TTL = 10 * 60 * 1000; // 10 minutes
const CLOCK_TOLERANCE_SECONDS = 60;

let discoveryCache: { issuerUrl: string; fetchedAt: number; document: OidcDiscoveryDocument } | null = null;
let jwksCache: { uri: string; fetchedAt: number; keys: crypto.JsonWebKey[] } | null = null;
const DISCOVERY_CACHE_TTL = 10 * 60 * 1000;
const JWKS_CACHE_TTL = 10 * 60 * 1000;

/** Clear cached discovery document and JWKS (used by tests). */
export function clearOidcCaches(): void {
  discoveryCache = null;
  jwksCache = null;
}

export function isOidcConfigured(): boolean {
  return !!(config.oidc.issuerUrl && config.oidc.clientId);
}

function base64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlDecode(input: string): Buffer {
  let b64 = input.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4 !== 0) b64 += '=';
  return Buffer.from(b64, 'base64');
}

async function fetchJson(url: string, init?: RequestInit): Promise<any> {
  const response = await fetch(url, init);
  if (!response.ok) {
    throw new Error(`HTTP ${response.status} from ${url}`);
  }
  return response.json();
}

/**
 * Resolve the provider's discovery document (.well-known/openid-configuration).
 * Cached for 10 minutes; verifies the discovered issuer matches the configured
 * issuer URL to guard against misconfiguration.
 */
async function getDiscovery(): Promise<OidcDiscoveryDocument> {
  const issuerUrl = config.oidc.issuerUrl;
  if (!issuerUrl) {
    throw new AuthenticationError('OIDC is not configured');
  }

  if (discoveryCache && discoveryCache.issuerUrl === issuerUrl && Date.now() - discoveryCache.fetchedAt < DISCOVERY_CACHE_TTL) {
    return discoveryCache.document;
  }

  const document = await fetchJson(`${issuerUrl}/.well-known/openid-configuration`) as OidcDiscoveryDocument;
  if (!document.authorization_endpoint || !document.token_endpoint || !document.jwks_uri) {
    throw new AuthenticationError('OIDC provider discovery document is incomplete');
  }
  // The discovered issuer must match the configured issuer (trailing slash normalized)
  if (document.issuer && document.issuer.replace(/\/+$/, '') !== issuerUrl) {
    throw new AuthenticationError('OIDC provider issuer mismatch');
  }

  discoveryCache = { issuerUrl, fetchedAt: Date.now(), document };
  return document;
}

async function getJwks(jwksUri: string): Promise<crypto.JsonWebKey[]> {
  if (jwksCache && jwksCache.uri === jwksUri && Date.now() - jwksCache.fetchedAt < JWKS_CACHE_TTL) {
    return jwksCache.keys;
  }
  const data = await fetchJson(jwksUri) as { keys?: crypto.JsonWebKey[] };
  if (!Array.isArray(data.keys)) {
    throw new AuthenticationError('OIDC provider JWKS response is invalid');
  }
  jwksCache = { uri: jwksUri, fetchedAt: Date.now(), keys: data.keys };
  return data.keys;
}

/**
 * Build the state parameter: base64url JSON payload + HMAC signature.
 * Carries the nonce and PKCE verifier so no server-side storage is needed.
 */
export function generateOidcState(): string {
  const payload: OidcStatePayload = {
    nonce: crypto.randomBytes(16).toString('hex'),
    verifier: base64UrlEncode(crypto.randomBytes(32)),
    iat: Date.now(),
  };
  const encoded = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
  const hmac = crypto.createHmac('sha256', config.jwtSecret).update(encoded).digest('hex').slice(0, 32);
  return `${encoded}.${hmac}`;
}

/** Verify the state signature + TTL and return the embedded payload. */
export function verifyOidcState(state: string): OidcStatePayload | null {
  const dot = state.lastIndexOf('.');
  if (dot <= 0) return null;
  const encoded = state.slice(0, dot);
  const hmac = state.slice(dot + 1);
  const expected = crypto.createHmac('sha256', config.jwtSecret).update(encoded).digest('hex').slice(0, 32);
  const hmacBuf = Buffer.from(hmac);
  const expectedBuf = Buffer.from(expected);
  if (hmacBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(hmacBuf, expectedBuf)) {
    return null;
  }

  let payload: OidcStatePayload;
  try {
    payload = JSON.parse(base64UrlDecode(encoded).toString('utf8'));
  } catch {
    return null;
  }
  if (!payload || typeof payload.nonce !== 'string' || typeof payload.verifier !== 'string' || typeof payload.iat !== 'number') {
    return null;
  }
  // iat is integrity-protected by the HMAC above, so the TTL check is safe
  if (Date.now() - payload.iat > OIDC_STATE_TTL) {
    return null;
  }

  return payload;
}

/**
 * Build the provider authorization URL (authorization-code flow + PKCE S256).
 */
export async function getAuthorizationUrl(state: string): Promise<string> {
  const discovery = await getDiscovery();
  const payload = verifyOidcState(state);
  if (!payload) {
    throw new AuthenticationError('Invalid OIDC state');
  }

  const challenge = base64UrlEncode(crypto.createHash('sha256').update(payload.verifier).digest());
  const params = new URLSearchParams({
    client_id: config.oidc.clientId,
    redirect_uri: config.oidc.redirectUri,
    response_type: 'code',
    scope: config.oidc.scopes || 'openid email profile',
    state,
    nonce: payload.nonce,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  return `${discovery.authorization_endpoint}?${params.toString()}`;
}

/** Exchange the authorization code for tokens (PKCE verifier included). */
async function exchangeCodeForTokens(code: string, verifier: string, redirectUri: string, tokenEndpoint: string): Promise<OidcTokenResponse> {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    client_id: config.oidc.clientId,
    code,
    redirect_uri: redirectUri,
    code_verifier: verifier,
  });
  if (config.oidc.clientSecret) {
    body.set('client_secret', config.oidc.clientSecret);
  }

  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body: body.toString(),
  });

  const data = await response.json().catch(() => ({})) as OidcTokenResponse;
  if (!response.ok || data.error) {
    logger.error('OIDC token exchange failed', { status: response.status, error: data.error });
    throw new AuthenticationError(data.error_description || 'OIDC token exchange failed');
  }
  return data;
}

/**
 * Verify an ID token: signature against the provider JWKS (RS256 / ES256),
 * plus issuer, audience, expiry and nonce claims.
 */
async function verifyIdToken(idToken: string, jwksUri: string, expectedNonce: string): Promise<Record<string, any>> {
  const parts = idToken.split('.');
  if (parts.length !== 3) {
    throw new AuthenticationError('Malformed OIDC ID token');
  }
  const [headerB64, payloadB64, signatureB64] = parts;

  let header: { alg?: string; kid?: string };
  let claims: Record<string, any>;
  try {
    header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
    claims = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
  } catch {
    throw new AuthenticationError('Malformed OIDC ID token');
  }

  if (header.alg !== 'RS256' && header.alg !== 'ES256') {
    throw new AuthenticationError(`Unsupported OIDC ID token algorithm: ${header.alg}`);
  }

  const keys = await getJwks(jwksUri);
  const candidates = keys.filter(k => (header.kid ? k.kid === header.kid : true));
  const signingInput = `${headerB64}.${payloadB64}`;
  const signature = base64UrlDecode(signatureB64);

  let verified = false;
  for (const jwk of candidates) {
    try {
      const key = crypto.createPublicKey({ key: jwk as any, format: 'jwk' } as any);
      if (header.alg === 'RS256') {
        const verifier = crypto.createVerify('RSA-SHA256');
        verifier.update(signingInput);
        verifier.end();
        if (verifier.verify(key, signature)) {
          verified = true;
          break;
        }
      } else {
        // ES256 JWS signatures are raw R||S; dsaEncoding:'ieee-p1363' accepts them directly
        const verifier = crypto.createVerify('SHA256');
        verifier.update(signingInput);
        verifier.end();
        if (verifier.verify({ key, dsaEncoding: 'ieee-p1363' } as any, signature)) {
          verified = true;
          break;
        }
      }
    } catch {
      // try next key
    }
  }
  if (!verified) {
    throw new AuthenticationError('OIDC ID token signature verification failed');
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || nowSeconds > claims.exp + CLOCK_TOLERANCE_SECONDS) {
    throw new AuthenticationError('OIDC ID token has expired');
  }
  if (typeof claims.iat === 'number' && claims.iat > nowSeconds + CLOCK_TOLERANCE_SECONDS) {
    throw new AuthenticationError('OIDC ID token issued-at is in the future');
  }
  if (typeof claims.iss !== 'string' || claims.iss.replace(/\/+$/, '') !== config.oidc.issuerUrl) {
    throw new AuthenticationError('OIDC ID token issuer mismatch');
  }
  const aud = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!aud.includes(config.oidc.clientId)) {
    throw new AuthenticationError('OIDC ID token audience mismatch');
  }
  if (claims.nonce !== expectedNonce) {
    throw new AuthenticationError('OIDC ID token nonce mismatch');
  }

  return claims;
}

/**
 * Complete the authorization-code exchange and return the verified identity.
 * `state` must be the exact value returned to the provider; `code` is the
 * authorization code from the callback query string.
 */
export async function authenticateWithCode(code: string, state: string): Promise<OidcIdentity> {
  if (!isOidcConfigured()) {
    throw new AuthenticationError('OIDC authentication is not configured');
  }

  const payload = verifyOidcState(state);
  if (!payload) {
    throw new AuthenticationError('Invalid or expired OIDC state');
  }

  const discovery = await getDiscovery();
  const tokens = await exchangeCodeForTokens(code, payload.verifier, config.oidc.redirectUri, discovery.token_endpoint);

  let identity: OidcIdentity | null = null;

  if (tokens.id_token) {
    const claims = await verifyIdToken(tokens.id_token, discovery.jwks_uri, payload.nonce);
    identity = {
      subject: String(claims.sub ?? ''),
      email: typeof claims.email === 'string' ? claims.email : '',
      name: typeof claims.name === 'string' ? claims.name : undefined,
      picture: typeof claims.picture === 'string' ? claims.picture : undefined,
    };
  } else if (tokens.access_token && discovery.userinfo_endpoint) {
    // No ID token returned — fall back to the userinfo endpoint
    const userinfo = await fetchJson(discovery.userinfo_endpoint, {
      headers: { Authorization: 'Bearer ' + tokens.access_token, Accept: 'application/json' },
    });
    identity = {
      subject: String(userinfo.sub ?? ''),
      email: typeof userinfo.email === 'string' ? userinfo.email : '',
      name: typeof userinfo.name === 'string' ? userinfo.name : undefined,
      picture: typeof userinfo.picture === 'string' ? userinfo.picture : undefined,
    };
  }

  if (!identity || !identity.subject) {
    throw new AuthenticationError('OIDC provider did not return a usable identity');
  }
  if (!identity.email) {
    throw new AuthenticationError('No email address returned by your OIDC provider');
  }

  // Normalize email to match express-validator's normalizeEmail() behaviour
  identity.email = identity.email.toLowerCase().trim();
  return identity;
}
