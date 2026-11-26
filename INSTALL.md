# Zyphra: all stages (welcome + reliability, paid membership, paid groups, talk to admin)

Copy each file into your project at the path shown. Everything else stays as it is.
Files marked NEW did not exist before.

## backend/
app.py, chat_db.py, platform_db.py, platform_routes.py, e2ee_routes.py
price_oracle.py (NEW), support_db.py (NEW)

## backend/migrations/   (applied automatically the next time the backend starts)
007_group_entry_fee_usd.sql (NEW)
008_support_threads.sql (NEW)

## backend/ (tests)
test_paid_membership_and_groups.py, test_platform_features.py, test_chat_e2ee.py,
test_send_performance.py, test_support.py (NEW)
Run:  TESTING=1 python -m pytest -q      (expect: 180 passed)

## frontend/src/
App.tsx, main.tsx

## frontend/src/components/
Header.tsx, AdminDashboard.tsx, Chat.tsx, PlatformViews.tsx,
PaidGroupAdmissionModal.tsx, PlatformAdmissionModal.tsx, WelcomeSplash.tsx, WelcomeSplash.css,
WelcomeGate.tsx (NEW), WelcomeGate.css (NEW), DotField.tsx (NEW),
SupportView.tsx (NEW), SupportConversation.tsx (NEW), AdminSupportInbox.tsx (NEW)

## frontend/src/services/
platformApi.ts, api.ts, e2eeApi.ts, resilientFetch.ts (NEW)

## Optional settings (backend environment)
(Active network, membership price and payment wallet are set ONLY in the Admin console at /Admin456 - not here.)
PAYMENT_PRICE_TOLERANCE_PCT  default 5      allowed ETH price movement between quote and payment
DB_POOL_MIN / DB_POOL_MAX    default 3 / 10 database connections kept ready
