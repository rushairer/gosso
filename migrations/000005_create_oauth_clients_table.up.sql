CREATE TABLE
    IF NOT EXISTS oauth_clients (
        id char(36) NOT NULL,
        name varchar(255) DEFAULT NULL,
        secret varchar(255) NOT NULL,
        callback text NOT NULL,
        created_at timestamp NULL DEFAULT NULL,
        updated_at timestamp NULL DEFAULT NULL,
        PRIMARY KEY (id)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;