import { describe, it, expect, vi, beforeEach } from 'vitest';

// ── Mock transitive dependencies ─────────────────────────────────────────────
vi.mock('@/utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

vi.mock('@/config/database.js', () => ({
  supabase: { from: vi.fn(), rpc: vi.fn() },
  connectDB: vi.fn(),
}));

// NOTE: vi.mock factories are hoisted — the config object must live inside the
// factory. Tests import config below and mutate config.oidc per test.
vi.mock('@/config/index.js', () => {
  const testConfig = {
    nodeEnv: 'test',
    jwtSecret: 'test-jwt-secret',
    apiKeySecret: 'test-api-key-secret',
    email: {
      transport: 'resend',
      resendApiKey: '',
      fromAddress: 'Idswyft <team@example.com>',
      smtp: { host: '', port: 587, secure: false, user: '', pass: '' },
    },
    github: { clientId: '', clientSecret: '', redirectUri: 'http://localhost/' },
    oidc: {
      issuerUrl: '',
      clientId: '',
      clientSecret: '',
      redirectUri: '',
      scopes: 'openid email profile',
    },
  };
  return { config: testConfig, default: testConfig };
});

import config from '@/config/index.js';

describe('developer OTP routes — OIDC enforcement', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    config.oidc.issuerUrl = '';
    config.oidc.clientId = '';
  });

  // catchAsync forwards handler errors to next() rather than rejecting, so
  // these assertions capture the error via the next() callback.
  async function invokeHandler(router: any, path: string, req: any, res: any): Promise<Error | null> {
    const layer = router.stack.find((l: any) => l.route?.path === path && l.route?.methods?.post);
    expect(layer).toBeDefined();
    const handler = layer.route.stack[layer.route.stack.length - 1].handle;
    let captured: Error | null = null;
    await handler(req, res, (err: any) => { captured = err ?? null; });
    return captured;
  }

  const okRes = () => ({ json: vi.fn(), status: vi.fn().mockReturnThis() }) as any;

  it('blocks developer OTP when OIDC is configured', async () => {
    config.oidc.issuerUrl = 'https://sso.example.com';
    config.oidc.clientId = 'portal';

    const { default: authRouter } = await import('../../routes/auth.js');
    const err = await invokeHandler(authRouter, '/developer/otp/send', { body: { email: 'dev@example.com' } }, okRes());
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toMatch(/OIDC SSO/);
  });

  it('blocks developer OTP verification when OIDC is configured', async () => {
    config.oidc.issuerUrl = 'https://sso.example.com';
    config.oidc.clientId = 'portal';

    const { default: authRouter } = await import('../../routes/auth.js');
    const err = await invokeHandler(authRouter, '/developer/otp/verify', { body: { email: 'dev@example.com', code: '123456' } }, okRes());
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toMatch(/OIDC SSO/);
  });

  it('blocks developer OTP registration when OIDC is configured', async () => {
    config.oidc.issuerUrl = 'https://sso.example.com';
    config.oidc.clientId = 'portal';

    const { default: authRouter } = await import('../../routes/auth.js');
    const err = await invokeHandler(authRouter, '/developer/otp/complete-registration', { body: { registration_token: 'tok', name: 'Dev' } }, okRes());
    expect(err).toBeInstanceOf(Error);
    expect(err!.message).toMatch(/OIDC SSO/);
  });

  it('does NOT block reviewer OTP when OIDC is configured (reviewers are invited operators)', async () => {
    config.oidc.issuerUrl = 'https://sso.example.com';
    config.oidc.clientId = 'portal';

    const { default: authRouter } = await import('../../routes/auth.js');
    const layer = (authRouter as any).stack.find(
      (l: any) => l.route?.path === '/reviewer/otp/send' && l.route?.methods?.post
    );
    expect(layer).toBeDefined();

    const handler = layer.route.stack[layer.route.stack.length - 1].handle;
    const req = { body: { email: 'reviewer@example.com' } } as any;
    const res = { json: vi.fn(), status: vi.fn().mockReturnThis() } as any;

    // Reviewer flow must still run — it will hit the (mocked) DB, not the OIDC guard
    const { supabase } = await import('@/config/database.js');
    (supabase.from as any).mockImplementation(() => ({
      select: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      neq: vi.fn().mockReturnThis(),
      limit: vi.fn().mockReturnThis(),
      single: vi.fn().mockResolvedValue({ data: null, error: { message: 'not found' } }),
    }));
    (supabase.rpc as any).mockResolvedValue({ data: true, error: null });

    await handler(req, res, vi.fn());
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      message: expect.stringContaining('If this email is registered as a reviewer'),
    }));
  });

  it('allows developer OTP when OIDC is NOT configured', async () => {
    const { default: authRouter } = await import('../../routes/auth.js');
    const layer = (authRouter as any).stack.find(
      (l: any) => l.route?.path === '/developer/otp/send' && l.route?.methods?.post
    );
    const handler = layer.route.stack[layer.route.stack.length - 1].handle;
    const req = { body: { email: 'dev@example.com' } } as any;
    const res = { json: vi.fn(), status: vi.fn().mockReturnThis() } as any;

    const { supabase } = await import('@/config/database.js');
    (supabase.rpc as any).mockResolvedValue({ data: true, error: null });
    (supabase.from as any).mockImplementation(() => ({
      select: vi.fn().mockReturnThis(),
      update: vi.fn().mockReturnThis(),
      insert: vi.fn().mockResolvedValue({ error: null }),
      eq: vi.fn().mockReturnThis(),
      is: vi.fn().mockResolvedValue({ data: null, error: null }),
      single: vi.fn().mockResolvedValue({ data: null, error: null }),
      then: (resolve: any) => resolve({ data: null, error: null }),
    }));

    await handler(req, res, vi.fn());
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      message: expect.stringContaining('verification code'),
    }));
  });

  it('exposes OIDC configuration state on the url endpoint', async () => {
    const { default: authRouter } = await import('../../routes/auth.js');
    const layer = (authRouter as any).stack.find(
      (l: any) => l.route?.path === '/developer/oidc/url' && l.route?.methods?.get
    );
    expect(layer).toBeDefined();

    // Not configured → { configured: false }
    const handler = layer.route.stack[layer.route.stack.length - 1].handle;
    const res1 = { json: vi.fn() } as any;
    await handler({} as any, res1, vi.fn());
    expect(res1.json).toHaveBeenCalledWith({ url: null, configured: false });
  });
});
