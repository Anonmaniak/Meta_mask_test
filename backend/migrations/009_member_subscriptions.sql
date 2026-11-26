-- ============================================================================
-- Migration 009: Monthly / Yearly subscriptions (platform membership + paid groups)
-- ============================================================================
-- One row per (member, scope). scope_type = 'platform' (scope_id 'platform') or 'group' (scope_id = group_id).
-- paid_until is extended by every verified payment: monthly = +30 days, yearly = +365 days.
CREATE TABLE IF NOT EXISTS member_subscriptions (
    user_id     VARCHAR(64)  NOT NULL,
    scope_type  VARCHAR(16)  NOT NULL,
    scope_id    VARCHAR(128) NOT NULL,
    paid_until  TIMESTAMP WITH TIME ZONE NOT NULL,
    last_period VARCHAR(8)   NOT NULL DEFAULT 'monthly',
    updated_at  TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, scope_type, scope_id)
);
CREATE INDEX IF NOT EXISTS idx_member_subs_scope ON member_subscriptions (scope_type, scope_id, paid_until);

-- Yearly price of a paid group in USD ('0' = automatic: 12 x the monthly price)
ALTER TABLE group_access_policies ADD COLUMN IF NOT EXISTS entry_fee_yearly_usd VARCHAR(32) NOT NULL DEFAULT '0';
