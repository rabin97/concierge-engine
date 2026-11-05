-- Demo user for local development (auth is the X-User-Id header locally; swap for JWT in prod)
INSERT INTO users (id, name, phone_e164, email, timezone, wa_opt_in_at)
VALUES ('11111111-1111-1111-1111-111111111111', 'Demo User', '+919999999999', 'demo@example.com',
        'Asia/Kolkata', now())
ON CONFLICT DO NOTHING;

INSERT INTO addresses (id, user_id, line1, city, pincode, is_default)
VALUES ('22222222-2222-2222-2222-222222222222', '11111111-1111-1111-1111-111111111111',
        '12, 4th Cross, HSR Layout', 'Bengaluru', '560102', true)
ON CONFLICT DO NOTHING;
