-- ============================================================================
-- Migration 013: replies in the Members' room
-- ----------------------------------------------------------------------------
-- A Members' room message can reply to an earlier one. Only the id is stored; the quote (who wrote
-- it and a short excerpt) is built from the original when the room is read, so a moderator deleting
-- the original also removes its text from every quote.
-- ============================================================================
ALTER TABLE public_chat_messages ADD COLUMN IF NOT EXISTS reply_to_message_id TEXT;
