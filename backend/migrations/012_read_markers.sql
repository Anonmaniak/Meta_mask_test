-- ============================================================================
-- Migration 012: unread counts for notifications
-- ----------------------------------------------------------------------------
-- How far each member has read each private chat ('dm:<conversation_id>') and group
-- ('group:<group_id>'). Used only to show that member their own unread badges; message contents
-- stay end-to-end encrypted. A '__baseline__' row marks that existing history was set as read.
-- (backend/read_markers_db.py also creates this table if it is missing.)
-- ============================================================================
CREATE TABLE IF NOT EXISTS chat_read_markers (
    user_id VARCHAR(64) NOT NULL,
    scope_key VARCHAR(96) NOT NULL,
    last_read_seq BIGINT NOT NULL DEFAULT 0,
    updated_bucket VARCHAR(40) NOT NULL,
    PRIMARY KEY (user_id, scope_key)
);
