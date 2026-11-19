-- ============================================================================
-- Migration 007: Paid groups are priced in USD (converted to ETH at payment time)
-- ============================================================================
ALTER TABLE group_access_policies ADD COLUMN IF NOT EXISTS entry_fee_usd VARCHAR(32) NOT NULL DEFAULT '0';
