import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import crypto from 'crypto';

// ── Mock transitive dependencies ─────────────────────────────────────────────
vi.mock('@/utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

// NOTE: vi.mock factories are hoisted — the config object must be defined
// inside the factory, not referenced from an outer variable.
vi.mock('@/config/index.js', () => {
  const testConfig = {
    nodeEnv: 'test',
    jwtSecret: 'test-jwt-secret-for-state-hmac',
    oidc: {
      issuerUrl: 'https://sso.example.com/realms/test',
      clientId: 'idswyft-developer-portal',
      clientSecret: 'oidc-client-secret',
      redirectUri: 'http://localhost/',
      scopes: 'openid email profile',
    },
  };
  return { config: testConfig, default: testConfig };
});

const ISSUER = 'https://sso.example.com/realms/test';
const CLIENT_ID = 'idswyft-developer-portal';

import {
  isOidcConfigured,
  generateOidcState,
  verifyOidcState,
  getAuthorizationUrl,
  authenticateWithCode,
  clearOidcCaches,
} from '../../services/oidcService.js';

const DISCOVERY_DOC = {
  issuer: ISSUER,
  authorization_endpoint: `${ISSUER}/protocol/openid-connect/auth`,
  token_endpoint: `${ISSUER}/protocol/openid-connect/token`,
  userinfo_endpoint: `${ISSUER}/protocol/openid-connect/userinfo`,
  jwks_uri: `${ISSUER}/protocol/openid-connect/certs`,
};

function mockFetchFor(routes: Record<string, (init?: RequestInit) => any>) {
  return vi.fn(async (input: any, init?: RequestInit) => {
    const url = String(input);
    for (const [prefix, handler] of Object.entries(routes)) {
      if (url.startsWith(prefix)) {
        const body = handler(init);
        return { ok: true, status: 200, json: async () => body, text: async () => JSON.stringify(body) } as any;
      }
    }
    return { ok: false, status: 404, json: async () => ({}), text: async () => 'not found' } as any;
  });
}

function signIdToken(claims: Record<string, any>, privateKey: crypto.KeyObject, kid: string): string {
  const b64 = (o: any) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const header = b64({ alg: 'RS256', kid, typ: 'JWT' });
  const payload = b64(claims);
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  signer.end();
  return `${header}.${payload}.${signer.sign(privateKey).toString('base64url')}`;
}

describe('oidcService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
    clearOidcCaches();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('isOidcConfigured', () => {
    it('returns true when issuer URL and client ID are set', () => {
      expect(isOidcConfigured()).toBe(true);
    });
  });

  describe('state generation + verification', () => {
    it('round-trips a generated state', () => {
      const state = generateOidcState();
      const payload = verifyOidcState(state);
      expect(payload).not.toBeNull();
      expect(payload!.nonce).toMatch(/^[a-f0-9]{32}$/);
      expect(payload!.verifier.length).toBeGreaterThan(20);
      expect(typeof payload!.iat).toBe('number');
    });

    it('rejects a tampered state', () => {
      const state = generateOidcState();
      const tampered = state.slice(0, -2) + 'zz';
      expect(verifyOidcState(tampered)).toBeNull();
    });

    it('rejects garbage', () => {
      expect(verifyOidcState('not-a-state')).toBeNull();
      expect(verifyOidcState('')).toBeNull();
    });

    it('rejects an expired state', () => {
      const state = generateOidcState();
      // Time-travel beyond the 10-minute TTL
      const now = Date.now();
      vi.spyOn(Date, 'now').mockReturnValue(now + 11 * 60 * 1000);
      expect(verifyOidcState(state)).toBeNull();
      vi.restoreAllMocks();
    });
  });

  describe('getAuthorizationUrl', () => {
    it('builds an authorization URL with PKCE from discovery', async () => {
      vi.stubGlobal('fetch', mockFetchFor({
        [`${ISSUER}/.well-known/openid-configuration`]: () => DISCOVERY_DOC,
      }));

      const state = generateOidcState();
      const url = await getAuthorizationUrl(state);
      const parsed = new URL(url);

      expect(url.startsWith(DISCOVERY_DOC.authorization_endpoint)).toBe(true);
      expect(parsed.searchParams.get('client_id')).toBe(CLIENT_ID);
      expect(parsed.searchParams.get('redirect_uri')).toBe('http://localhost/');
      expect(parsed.searchParams.get('response_type')).toBe('code');
      expect(parsed.searchParams.get('scope')).toBe('openid email profile');
      expect(parsed.searchParams.get('state')).toBe(state);
      expect(parsed.searchParams.get('nonce')).toBeTruthy();
      expect(parsed.searchParams.get('code_challenge')).toBeTruthy();
      expect(parsed.searchParams.get('code_challenge_method')).toBe('S256');
    });

    it('rejects when the discovered issuer does not match configuration', async () => {
      vi.stubGlobal('fetch', mockFetchFor({
        [`${ISSUER}/.well-known/openid-configuration`]: () => ({ ...DISCOVERY_DOC, issuer: 'https://evil.example.com' }),
      }));

      await expect(getAuthorizationUrl(generateOidcState())).rejects.toThrow('issuer mismatch');
    });
  });

  describe('authenticateWithCode', () => {
    it('returns a verified identity for a valid code + ID token', async () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256', use: 'sig' };

      vi.stubGlobal('fetch', mockFetchFor({
        [`${ISSUER}/.well-known/openid-configuration`]: () => DISCOVERY_DOC,
        [DISCOVERY_DOC.jwks_uri]: () => ({ keys: [jwk] }),
        [DISCOVERY_DOC.token_endpoint]: (init) => {
          const body = String(init?.body);
          expect(body).toContain('grant_type=authorization_code');
          expect(body).toContain('code_verifier=');
          expect(body).toContain('client_secret=');
          return { id_token: idToken, token_type: 'Bearer' };
        },
      }));

      const state = generateOidcState();
      const idToken = signIdToken({
        iss: ISSUER,
        sub: 'oidc-subject-123',
        aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 300,
        iat: Math.floor(Date.now() / 1000),
        nonce: verifyOidcState(state)!.nonce,
        email: 'Dev@Example.com',
        name: 'Dev User',
        picture: 'https://example.com/avatar.png',
      }, privateKey, 'test-key');

      const identity = await authenticateWithCode('auth-code-123', state);
      expect(identity.subject).toBe('oidc-subject-123');
      expect(identity.email).toBe('dev@example.com'); // normalized
      expect(identity.name).toBe('Dev User');
      expect(identity.picture).toBe('https://example.com/avatar.png');
    });

    it('rejects an ID token with a wrong audience', async () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1' };

      vi.stubGlobal('fetch', mockFetchFor({
        [`${ISSUER}/.well-known/openid-configuration`]: () => DISCOVERY_DOC,
        [DISCOVERY_DOC.jwks_uri]: () => ({ keys: [jwk] }),
        [DISCOVERY_DOC.token_endpoint]: () => ({ id_token: badToken }),
      }));

      const state = generateOidcState();
      const badToken = signIdToken({
        iss: ISSUER, sub: 's1', aud: 'some-other-client',
        exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000),
        nonce: verifyOidcState(state)!.nonce, email: 'a@b.com',
      }, privateKey, 'k1');

      await expect(authenticateWithCode('code', state)).rejects.toThrow('audience mismatch');
    });

    it('rejects an ID token with a wrong nonce', async () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1' };

      vi.stubGlobal('fetch', mockFetchFor({
        [`${ISSUER}/.well-known/openid-configuration`]: () => DISCOVERY_DOC,
        [DISCOVERY_DOC.jwks_uri]: () => ({ keys: [jwk] }),
        [DISCOVERY_DOC.token_endpoint]: () => ({ id_token: badToken }),
      }));

      const state = generateOidcState();
      const badToken = signIdToken({
        iss: ISSUER, sub: 's1', aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000),
        nonce: 'attacker-nonce', email: 'a@b.com',
      }, privateKey, 'k1');

      await expect(authenticateWithCode('code', state)).rejects.toThrow('nonce mismatch');
    });

    it('rejects an ID token signed with the wrong key', async () => {
      const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const attacker = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1' };

      vi.stubGlobal('fetch', mockFetchFor({
        [`${ISSUER}/.well-known/openid-configuration`]: () => DISCOVERY_DOC,
        [DISCOVERY_DOC.jwks_uri]: () => ({ keys: [jwk] }),
        [DISCOVERY_DOC.token_endpoint]: () => ({ id_token: forged }),
      }));

      const state = generateOidcState();
      const forged = signIdToken({
        iss: ISSUER, sub: 's1', aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000),
        nonce: verifyOidcState(state)!.nonce, email: 'a@b.com',
      }, attacker.privateKey, 'k1');

      await expect(authenticateWithCode('code', state)).rejects.toThrow('signature verification failed');
    });

    it('rejects when the token endpoint returns an error', async () => {
      vi.stubGlobal('fetch', mockFetchFor({
        [`${ISSUER}/.well-known/openid-configuration`]: () => DISCOVERY_DOC,
        [DISCOVERY_DOC.token_endpoint]: () => ({ error: 'invalid_grant', error_description: 'Code expired' }),
      }));

      await expect(authenticateWithCode('bad-code', generateOidcState())).rejects.toThrow('Code expired');
    });

    it('rejects a tampered state before contacting the provider', async () => {
      const fetchMock = mockFetchFor({});
      vi.stubGlobal('fetch', fetchMock);

      await expect(authenticateWithCode('code', 'tampered.state')).rejects.toThrow('Invalid or expired OIDC state');
      expect(fetchMock).not.toHaveBeenCalled();
    });

    it('rejects when no email is returned', async () => {
      const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
      const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'k1' };

      vi.stubGlobal('fetch', mockFetchFor({
        [`${ISSUER}/.well-known/openid-configuration`]: () => DISCOVERY_DOC,
        [DISCOVERY_DOC.jwks_uri]: () => ({ keys: [jwk] }),
        [DISCOVERY_DOC.token_endpoint]: () => ({ id_token: noEmailToken }),
      }));

      const state = generateOidcState();
      const noEmailToken = signIdToken({
        iss: ISSUER, sub: 's1', aud: CLIENT_ID,
        exp: Math.floor(Date.now() / 1000) + 300, iat: Math.floor(Date.now() / 1000),
        nonce: verifyOidcState(state)!.nonce,
      }, privateKey, 'k1');

      await expect(authenticateWithCode('code', state)).rejects.toThrow('No email address');
    });
  });
});
