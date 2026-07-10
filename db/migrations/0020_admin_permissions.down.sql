UPDATE roles
SET permissions = COALESCE(permissions, '[]'::jsonb) - 'admin:*',
    updated_at = NOW()
WHERE name = 'admin' AND deleted_at IS NULL;
