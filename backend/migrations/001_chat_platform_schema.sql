-- ============================================================================
-- Migration 001: Zyphra Ethereum Wallet-Linked Chat Platform Schema
-- Target: PostgreSQL (Neon DB / Supabase / Standard PostgreSQL 14+)
-- Zero-Payment, Zero-MongoDB Unified Relational Architecture
-- ============================================================================

CREATE TABLE IF NOT EXISTS schema_migrations (
    version VARCHAR(64) PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 1. Core Permanent User Identity (immutable user_id, starts at Level 7)
CREATE TABLE IF NOT EXISTS chat_users (
    user_id VARCHAR(64) PRIMARY KEY,
    username VARCHAR(64) UNIQUE,
    display_name VARCHAR(80),
    bio VARCHAR(280),
    avatar_url VARCHAR(512),
    username_changed_at TIMESTAMP WITH TIME ZONE,
    current_level INT NOT NULL DEFAULT 7,
    highest_level INT NOT NULL DEFAULT 7,
    qualifying_balance_wei VARCHAR(78) NOT NULL DEFAULT '0',
    qualifying_chain_id INT NOT NULL DEFAULT 1,
    last_balance_verified_at TIMESTAMP WITH TIME ZONE,
    level_grace_expires_at TIMESTAMP WITH TIME ZONE,
    account_status VARCHAR(24) NOT NULL DEFAULT 'active',
    suspended_until TIMESTAMP WITH TIME ZONE,
    suspension_reason VARCHAR(280),
    show_online_presence BOOLEAN NOT NULL DEFAULT TRUE,
    send_read_receipts BOOLEAN NOT NULL DEFAULT TRUE,
    identity_version INT NOT NULL DEFAULT 1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Safe idempotent upgrades for existing deployments
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS display_name VARCHAR(80);
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS bio VARCHAR(280);
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS avatar_url VARCHAR(512);
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS username_changed_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS current_level INT NOT NULL DEFAULT 7;
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS highest_level INT NOT NULL DEFAULT 7;
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS qualifying_balance_wei VARCHAR(78) NOT NULL DEFAULT '0';
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS qualifying_chain_id INT NOT NULL DEFAULT 1;
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS last_balance_verified_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS level_grace_expires_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS account_status VARCHAR(24) NOT NULL DEFAULT 'active';
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS suspended_until TIMESTAMP WITH TIME ZONE;
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS suspension_reason VARCHAR(280);
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS show_online_presence BOOLEAN NOT NULL DEFAULT TRUE;
ALTER TABLE chat_users ADD COLUMN IF NOT EXISTS send_read_receipts BOOLEAN NOT NULL DEFAULT TRUE;

CREATE UNIQUE INDEX IF NOT EXISTS idx_chat_users_username_lower
    ON chat_users (LOWER(username))
    WHERE username IS NOT NULL;

-- 2. Username History & Reservation Quarantine
CREATE TABLE IF NOT EXISTS username_history (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    old_username VARCHAR(64),
    new_username VARCHAR(64) NOT NULL,
    reserved_until TIMESTAMP WITH TIME ZONE,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_username_hist_user ON username_history(user_id, changed_at DESC);
CREATE INDEX IF NOT EXISTS idx_username_hist_old_lower ON username_history(LOWER(old_username));

-- 3. Wallet Associations & Change History
CREATE TABLE IF NOT EXISTS chat_user_wallets (
    wallet_address VARCHAR(42) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    is_primary BOOLEAN NOT NULL DEFAULT TRUE,
    status VARCHAR(24) NOT NULL DEFAULT 'active',
    linked_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_wallets_user ON chat_user_wallets(user_id);

CREATE TABLE IF NOT EXISTS wallet_change_history (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    action VARCHAR(32) NOT NULL,
    old_wallet VARCHAR(42),
    new_wallet VARCHAR(42),
    performed_by VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_wallet_hist_user ON wallet_change_history(user_id, created_at DESC);

-- 4. SIWE Challenges & Hashed Sessions
CREATE TABLE IF NOT EXISTS chat_auth_challenges (
    challenge_id VARCHAR(64) PRIMARY KEY,
    wallet_address VARCHAR(42) NOT NULL,
    user_id VARCHAR(64),
    purpose VARCHAR(32) NOT NULL,
    nonce VARCHAR(64) NOT NULL,
    message TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS chat_auth_sessions (
    session_id VARCHAR(64) PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    wallet_address VARCHAR(42) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON chat_auth_sessions(user_id);

-- 5. Configurable Wallet-Based Levels (Starting at Level 7) & RPC Snapshots
CREATE TABLE IF NOT EXISTS level_definitions (
    level INT PRIMARY KEY,
    name VARCHAR(80) NOT NULL,
    description VARCHAR(280) NOT NULL DEFAULT '',
    min_balance_wei VARCHAR(78) NOT NULL DEFAULT '0',
    max_balance_wei VARCHAR(78),
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    privileges_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    policy_version INT NOT NULL DEFAULT 1,
    effective_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS wallet_balance_snapshots (
    snapshot_id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    wallet_address VARCHAR(42) NOT NULL,
    chain_id INT NOT NULL,
    balance_wei VARCHAR(78) NOT NULL,
    block_number BIGINT NOT NULL,
    rpc_source VARCHAR(64) NOT NULL DEFAULT 'verified_rpc',
    verified_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_bal_snap_user ON wallet_balance_snapshots(user_id, verified_at DESC);

CREATE TABLE IF NOT EXISTS level_history (
    id BIGSERIAL PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    previous_level INT NOT NULL,
    new_level INT NOT NULL,
    qualifying_balance_wei VARCHAR(78) NOT NULL,
    block_number BIGINT,
    reason VARCHAR(120) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_lvl_hist_user ON level_history(user_id, created_at DESC);

-- 6. Open Public Chat Room (Readable Feed + Configurable Guest Policy)
CREATE TABLE IF NOT EXISTS public_chat_messages (
    seq BIGSERIAL PRIMARY KEY,
    message_id VARCHAR(64) NOT NULL UNIQUE,
    author_user_id VARCHAR(64) REFERENCES chat_users(user_id),
    guest_id VARCHAR(48),
    display_name VARCHAR(80) NOT NULL,
    author_level INT NOT NULL DEFAULT 7,
    is_guest BOOLEAN NOT NULL DEFAULT FALSE,
    content TEXT NOT NULL,
    edited_at TIMESTAMP WITH TIME ZONE,
    deleted BOOLEAN NOT NULL DEFAULT FALSE,
    deleted_by VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_pub_chat_seq ON public_chat_messages(seq DESC);

-- 7. Group Access Policies, Invite Links & Join Requests
CREATE TABLE IF NOT EXISTS group_access_policies (
    group_id VARCHAR(64) PRIMARY KEY,
    description VARCHAR(500) NOT NULL DEFAULT '',
    avatar_url VARCHAR(512),
    visibility VARCHAR(24) NOT NULL DEFAULT 'invite_only',
    min_level INT NOT NULL DEFAULT 7,
    min_eth_balance_wei VARCHAR(78) NOT NULL DEFAULT '0',
    require_invitation BOOLEAN NOT NULL DEFAULT TRUE,
    updated_by VARCHAR(64),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS group_invite_links (
    invite_code VARCHAR(48) PRIMARY KEY,
    group_id VARCHAR(64) NOT NULL,
    created_by VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_uses INT NOT NULL DEFAULT 25,
    use_count INT NOT NULL DEFAULT 0,
    revoked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_grp_invites_group ON group_invite_links(group_id);

CREATE TABLE IF NOT EXISTS group_join_requests (
    request_id VARCHAR(64) PRIMARY KEY,
    group_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    invite_code VARCHAR(48),
    status VARCHAR(24) NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP WITH TIME ZONE
);
CREATE INDEX IF NOT EXISTS idx_grp_join_req ON group_join_requests(group_id, status);

-- 8. User Blocks, DM Read Receipts, Abuse Reports & Moderation
CREATE TABLE IF NOT EXISTS user_blocks (
    blocker_user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    blocked_user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    reason VARCHAR(200) NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (blocker_user_id, blocked_user_id)
);

CREATE TABLE IF NOT EXISTS chat_dm_receipts (
    conversation_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    last_read_seq BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (conversation_id, user_id)
);

CREATE TABLE IF NOT EXISTS message_reports (
    report_id VARCHAR(64) PRIMARY KEY,
    reporter_user_id VARCHAR(64) NOT NULL REFERENCES chat_users(user_id),
    target_user_id VARCHAR(64),
    scope_type VARCHAR(24) NOT NULL,
    scope_id VARCHAR(64) NOT NULL,
    message_id VARCHAR(64),
    reason VARCHAR(80) NOT NULL,
    details VARCHAR(1000) NOT NULL DEFAULT '',
    status VARCHAR(24) NOT NULL DEFAULT 'open',
    resolution_note VARCHAR(500),
    reviewed_by VARCHAR(64),
    reviewed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_reports_status ON message_reports(status, created_at DESC);

CREATE TABLE IF NOT EXISTS moderation_actions (
    action_id VARCHAR(64) PRIMARY KEY,
    moderator_user_id VARCHAR(64) NOT NULL,
    target_user_id VARCHAR(64),
    target_type VARCHAR(32) NOT NULL,
    target_id VARCHAR(64) NOT NULL,
    action_type VARCHAR(48) NOT NULL,
    reason VARCHAR(500) NOT NULL DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- 9. Admin RBAC, Platform Settings & Immutable Audit Logs
CREATE TABLE IF NOT EXISTS admin_roles (
    user_id VARCHAR(64) PRIMARY KEY REFERENCES chat_users(user_id),
    role VARCHAR(24) NOT NULL,
    granted_by VARCHAR(64) NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS platform_settings (
    setting_key VARCHAR(64) PRIMARY KEY,
    setting_value_json JSONB NOT NULL,
    updated_by VARCHAR(64),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
    log_id BIGSERIAL PRIMARY KEY,
    actor_user_id VARCHAR(64) NOT NULL,
    action VARCHAR(80) NOT NULL,
    entity_type VARCHAR(48) NOT NULL,
    entity_id VARCHAR(64) NOT NULL,
    details_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at DESC);
