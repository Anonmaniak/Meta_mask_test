-- ============================================================================
-- Migration 004: Dual Qualification Requirements for Level Definitions
-- Adds independent minimum verified payment requirement (min_payment_wei)
-- ============================================================================

ALTER TABLE level_definitions
ADD COLUMN IF NOT EXISTS min_payment_wei VARCHAR(78) NOT NULL DEFAULT '0';

