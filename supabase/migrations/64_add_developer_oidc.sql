-- Migration: Add OIDC subject column to developers table
-- Generic OpenID Connect login for the developer portal (alternative to email OTP)

ALTER TABLE developers
  ADD COLUMN IF NOT EXISTS oidc_subject TEXT UNIQUE;

CREATE INDEX IF NOT EXISTS idx_developers_oidc_subject
  ON developers (oidc_subject) WHERE oidc_subject IS NOT NULL;
