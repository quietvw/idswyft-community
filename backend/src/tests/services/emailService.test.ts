import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ── Mock transitive dependencies ─────────────────────────────────────────────
vi.mock('@/utils/logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

// NOTE: vi.mock factories are hoisted — use vi.hoisted for shared mocks and
// define the mutable config inside the factory.
const { sendMailMock, createTransportMock } = vi.hoisted(() => {
  const sendMailMock = vi.fn();
  const createTransportMock = vi.fn(() => ({ sendMail: sendMailMock }));
  return { sendMailMock, createTransportMock };
});
vi.mock('nodemailer', () => ({
  default: { createTransport: createTransportMock },
  createTransport: createTransportMock,
}));

vi.mock('@/config/index.js', () => {
  const baseConfig = {
    nodeEnv: 'test',
    email: {
      transport: 'resend',
      resendApiKey: '',
      fromAddress: 'Idswyft <team@example.com>',
      smtp: { host: '', port: 587, secure: false, user: '', pass: '' },
    },
  };
  return { config: baseConfig, default: baseConfig };
});

import config from '@/config/index.js';
const baseConfig = config as any;

describe('emailService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
    sendMailMock.mockResolvedValue({ messageId: 'smtp-msg-1' });
    baseConfig.email.transport = 'resend';
    baseConfig.email.resendApiKey = '';
    baseConfig.email.smtp = { host: '', port: 587, secure: false, user: '', pass: '' };
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const options = { to: 'dev@example.com', subject: 'Test', html: '<p>hi</p>', text: 'hi' };

  it('logs to console when no transport is configured', async () => {
    const { EmailService } = await import('../../services/emailService.js');
    const service = new EmailService();

    expect(service.isConfigured).toBe(false);
    expect(await service.sendEmail(options)).toBe(true);

    const { logger } = await import('@/utils/logger.js');
    expect(logger.info).toHaveBeenCalledWith(expect.stringContaining('[DEV] Email to dev@example.com'));
  });

  it('sends via Resend when only RESEND_API_KEY is set', async () => {
    baseConfig.email.resendApiKey = 're_test_key';
    const fetchMock = vi.fn(async () => ({
      ok: true, status: 200,
      json: async () => ({ id: 'resend-id-1' }),
      text: async () => '',
    }));
    vi.stubGlobal('fetch', fetchMock);

    const { EmailService } = await import('../../services/emailService.js');
    const service = new EmailService();

    expect(service.isConfigured).toBe(true);
    expect(await service.sendEmail(options)).toBe(true);
    expect(fetchMock).toHaveBeenCalledWith('https://api.resend.com/emails', expect.objectContaining({ method: 'POST' }));
    expect(createTransportMock).not.toHaveBeenCalled();
  });

  it('sends via SMTP when SMTP_HOST is set (preferred over Resend)', async () => {
    baseConfig.email.resendApiKey = 're_test_key';
    baseConfig.email.smtp = { host: 'smtp.example.com', port: 587, secure: false, user: 'u', pass: 'p' };
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const { EmailService } = await import('../../services/emailService.js');
    const service = new EmailService();

    expect(service.isConfigured).toBe(true);
    expect(createTransportMock).toHaveBeenCalledWith({
      host: 'smtp.example.com', port: 587, secure: false, auth: { user: 'u', pass: 'p' },
    });

    expect(await service.sendEmail(options)).toBe(true);
    expect(sendMailMock).toHaveBeenCalledWith({
      from: 'Idswyft <team@example.com>',
      to: 'dev@example.com',
      subject: 'Test',
      html: '<p>hi</p>',
      text: 'hi',
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('omits auth when no SMTP user is configured', async () => {
    baseConfig.email.smtp = { host: 'mail.internal', port: 25, secure: false, user: '', pass: '' };

    const { EmailService } = await import('../../services/emailService.js');
    new EmailService();

    expect(createTransportMock).toHaveBeenCalledWith({
      host: 'mail.internal', port: 25, secure: false, auth: undefined,
    });
  });

  it('returns false when the SMTP send fails', async () => {
    baseConfig.email.smtp = { host: 'smtp.example.com', port: 587, secure: false, user: 'u', pass: 'p' };
    sendMailMock.mockRejectedValueOnce(new Error('connection refused'));

    const { EmailService } = await import('../../services/emailService.js');
    const service = new EmailService();

    expect(await service.sendEmail(options)).toBe(false);
  });

  it('returns false when the Resend API errors', async () => {
    baseConfig.email.resendApiKey = 're_test_key';
    vi.stubGlobal('fetch', vi.fn(async () => ({
      ok: false, status: 403,
      json: async () => ({}),
      text: async () => 'forbidden',
    })));

    const { EmailService } = await import('../../services/emailService.js');
    const service = new EmailService();

    expect(await service.sendEmail(options)).toBe(false);
  });

  it('sendOtpEmail composes the OTP template and sends it', async () => {
    baseConfig.email.smtp = { host: 'smtp.example.com', port: 465, secure: true, user: 'u', pass: 'p' };

    const { EmailService } = await import('../../services/emailService.js');
    const service = new EmailService();

    expect(await service.sendOtpEmail('dev@example.com', '123456')).toBe(true);
    expect(sendMailMock).toHaveBeenCalledWith(expect.objectContaining({
      to: 'dev@example.com',
      subject: 'Your Idswyft verification code',
      text: expect.stringContaining('123456'),
    }));
    const html = (sendMailMock.mock.calls[0][0] as any).html;
    expect(html).toContain('123456');
  });
});
