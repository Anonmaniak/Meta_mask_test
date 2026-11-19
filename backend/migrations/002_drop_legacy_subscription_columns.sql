-- ============================================================================
-- Migration 002: Drop Legacy Payment / Subscription Columns (Idempotent)
-- Ensures pure Chat-Only schema with zero payment or subscription remnants.
-- ============================================================================

ALTER TABLE chat_users DROP COLUMN IF EXISTS subscription_tier;
ALTER TABLE chat_users DROP COLUMN IF EXISTS subscription_expires_at;
ALTER TABLE chat_groups DROP COLUMN IF EXISTS paid_tier_required;

