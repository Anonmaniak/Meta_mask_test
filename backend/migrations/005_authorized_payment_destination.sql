-- ============================================================================
-- Migration 005: Authorized Payment Destination & Recipient Verification
-- Target: PostgreSQL (Neon DB / Standard PostgreSQL 14+)
-- ============================================================================

-- Add recipient_address column to payment_records to record authorized destination
ALTER TABLE payment_records ADD COLUMN IF NOT EXISTS recipient_address VARCHAR(42);

-- Index for auditing and querying payment records by recipient address
CREATE INDEX IF NOT EXISTS idx_payment_records_recipient
    ON payment_records (recipient_address);

