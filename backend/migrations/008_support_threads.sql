-- ============================================================================
-- Migration 008: "Talk to admin" support conversations
-- ============================================================================
CREATE TABLE IF NOT EXISTS support_threads (
    thread_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    last_message_at TEXT NOT NULL,
    last_sender_role TEXT NOT NULL DEFAULT 'user',
    user_unread INTEGER NOT NULL DEFAULT 0,
    admin_unread INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_support_threads_user ON support_threads(user_id, last_message_at DESC);
CREATE INDEX IF NOT EXISTS idx_support_threads_status ON support_threads(status, last_message_at DESC);

CREATE TABLE IF NOT EXISTS support_messages (
    message_id TEXT PRIMARY KEY,
    thread_id TEXT NOT NULL,
    sender_role TEXT NOT NULL,
    sender_id TEXT,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_support_messages_thread ON support_messages(thread_id, created_at);
