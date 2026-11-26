-- ============================================================================
-- Migration 011: files and images in the Members' room
-- ----------------------------------------------------------------------------
-- The Members' room is readable by every paid member and moderated, so its files are stored as-is
-- (NOT end-to-end encrypted: private chats and groups keep their device-side encrypted attachments).
-- A file is uploaded first (message_id NULL), then attached to exactly one message when it is posted.
-- Unattached uploads older than 24 hours and files of deleted messages are purged (data_b64 = NULL).
-- ============================================================================
CREATE TABLE IF NOT EXISTS public_chat_attachments (
    attachment_id TEXT PRIMARY KEY,
    uploader_user_id TEXT NOT NULL,
    message_id TEXT,
    file_name TEXT NOT NULL,
    mime_type TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'file',
    byte_length INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    data_b64 TEXT,
    deleted INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_public_chat_attachments_message ON public_chat_attachments(message_id);
CREATE INDEX IF NOT EXISTS idx_public_chat_attachments_uploader ON public_chat_attachments(uploader_user_id, created_at);
