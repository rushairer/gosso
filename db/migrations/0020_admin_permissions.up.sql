-- Grant the built-in administrator the explicit wildcard required by the
-- fine-grained admin middleware. Custom administrator roles should use the
-- narrower admin:users:read, admin:users:manage, and admin:audit:read values.
UPDATE roles
SET permissions = COALESCE(permissions, '[]'::jsonb) || '["admin:*"]'::jsonb,
    updated_at = NOW()
WHERE name = 'admin'
  AND deleted_at IS NULL
  AND NOT (COALESCE(permissions, '[]'::jsonb) ? 'admin:*');
