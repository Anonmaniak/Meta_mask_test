-- ============================================================================
-- Migration 006: Direct Platform Admission Paywall & Paid Groups
-- ============================================================================

-- 1. Add Paid Group policy fields
ALTER TABLE group_access_policies ADD COLUMN IF NOT EXISTS is_paid BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE group_access_policies ADD COLUMN IF NOT EXISTS entry_fee_eth VARCHAR(32) NOT NULL DEFAULT '0';
ALTER TABLE group_access_policies ADD COLUMN IF NOT EXISTS entry_fee_wei VARCHAR(78) NOT NULL DEFAULT '0';

-- 2. Add Purpose & Target to Payment Records
ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS purpose VARCHAR(32) NOT NULL DEFAULT 'platform_entry';
ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS target_id VARCHAR(128);

-- 3. Add Platform Paid Member status on Chat Users
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS is_platform_paid BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS platform_paid_at TIMESTAMP WITH TIME ZONE;

-- 4. Create supporting indexes
CREATE INDEX IF NOT EXISTS idx_payment_records_purpose_target ON payment_records(purpose, target_id);
CREATE INDEX IF NOT EXISTS idx_group_policies_is_paid ON group_access_policies(is_paid);
