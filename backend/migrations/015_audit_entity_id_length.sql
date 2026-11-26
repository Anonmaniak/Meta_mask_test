-- ============================================================================
-- Migration 015: audit_logs.entity_id fits a transaction hash
-- ----------------------------------------------------------------------------
-- A transaction hash is 66 characters ("0x" + 64 hex) but entity_id was VARCHAR(64), so on PostgreSQL
-- the audit entry for a payment on an unsupported network, or while the payout address is not set,
-- failed with "value too long" and the member got HTTP 500 instead of the intended clear error.
-- Widening a VARCHAR only changes metadata (no table rewrite). Runs only while the column is shorter.
-- ============================================================================
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_name = 'audit_logs' AND column_name = 'entity_id'
          AND character_maximum_length IS NOT NULL AND character_maximum_length < 128
    ) THEN
        ALTER TABLE audit_logs ALTER COLUMN entity_id TYPE VARCHAR(128);
    END IF;
END $$;
