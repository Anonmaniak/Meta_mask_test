-- ============================================================================
-- Migration 010 (runs ONCE, tracked by schema_migrations): grandfather existing payers
-- ============================================================================
-- Before subscriptions, a payment bought permanent access. So nobody is locked out the moment this ships,
-- everyone who already paid (or is already inside a paid group) gets 30 days to renew.
INSERT INTO member_subscriptions (user_id, scope_type, scope_id, paid_until, last_period)
SELECT DISTINCT u.user_id, 'platform', 'platform', CURRENT_TIMESTAMP + INTERVAL '30 days', 'monthly'
FROM chat_users u
WHERE u.is_platform_paid = TRUE
ON CONFLICT (user_id, scope_type, scope_id) DO NOTHING;

INSERT INTO member_subscriptions (user_id, scope_type, scope_id, paid_until, last_period)
SELECT DISTINCT p.user_id, 'group', p.target_id, CURRENT_TIMESTAMP + INTERVAL '30 days', 'monthly'
FROM payment_records p
WHERE p.status = 'verified' AND p.purpose = 'group_entry' AND p.target_id IS NOT NULL
ON CONFLICT (user_id, scope_type, scope_id) DO NOTHING;

INSERT INTO member_subscriptions (user_id, scope_type, scope_id, paid_until, last_period)
SELECT DISTINCT m.user_id, 'group', m.group_id, CURRENT_TIMESTAMP + INTERVAL '30 days', 'monthly'
FROM chat_group_members m
JOIN group_access_policies g ON g.group_id = m.group_id
WHERE m.status = 'active' AND g.is_paid = TRUE
ON CONFLICT (user_id, scope_type, scope_id) DO NOTHING;
