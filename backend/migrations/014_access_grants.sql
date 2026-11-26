-- ============================================================================
-- Migration 014: free access granted by an admin (no payment needed)
-- ----------------------------------------------------------------------------
-- One row per (member, scope). scope_type = 'platform' (scope_id 'platform') for the membership,
-- or 'group' (scope_id = group_id) for one paid group / one group with a minimum balance.
-- Kept apart from member_subscriptions on purpose: those rows are real payments (and feed the
-- "paid members" numbers); a grant is a gift from the admin, can be switched off, and can be timed.
--   expires_at NULL  = no end date (until the admin revokes it)
--   revoked_at set   = switched off (the row stays as a record of who granted what)
-- ============================================================================
CREATE TABLE IF NOT EXISTS access_grants (
    user_id    VARCHAR(64)  NOT NULL,
    scope_type VARCHAR(16)  NOT NULL,
    scope_id   VARCHAR(128) NOT NULL,
    granted_by VARCHAR(64)  NOT NULL,
    note       VARCHAR(200) NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by VARCHAR(64),
    PRIMARY KEY (user_id, scope_type, scope_id)
);
CREATE INDEX IF NOT EXISTS idx_access_grants_scope ON access_grants (scope_type, scope_id);
