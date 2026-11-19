-- ============================================================================
-- Migration 003: Authoritative Server-Side Verified Payment Records
-- Target: PostgreSQL (Neon DB / Standard PostgreSQL 14+)
-- ============================================================================

CREATE TABLE IF NOT EXISTS payment_records (
    payment_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    wallet_address VARCHAR(42),
    amount_atomic VARCHAR(78) NOT NULL DEFAULT '0',
    amount_formatted VARCHAR(48) NOT NULL DEFAULT '0',
    currency VARCHAR(16) NOT NULL DEFAULT 'ETH',
    network VARCHAR(32) NOT NULL DEFAULT 'ethereum',
    chain_id INT,
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    transaction_reference VARCHAR(128) NOT NULL UNIQUE,
    block_number BIGINT,
    verification_source VARCHAR(64) NOT NULL DEFAULT 'ethereum_rpc',
    verified_at TIMESTAMP WITH TIME ZONE,
    error_message VARCHAR(500),
    retry_count INT NOT NULL DEFAULT 0,
    metadata_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_records_tx_ref
    ON payment_records (transaction_reference);

CREATE INDEX IF NOT EXISTS idx_payment_records_user
    ON payment_records (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_payment_records_status
    ON payment_records (status);

