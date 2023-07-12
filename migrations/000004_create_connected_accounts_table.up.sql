CREATE TABLE
    IF NOT EXISTS connected_accounts (
        id bigint (20) unsigned NOT NULL AUTO_INCREMENT,
        user_id char(36) NOT NULL,
        provider_id bigint (20) unsigned NOT NULL,
        provider_user_id varchar(255) NOT NULL,
        name varchar(255) NOT NULL,
        email varchar(255) NOT NULL,
        phone varchar(255) NOT NULL,
        location varchar(255) NOT NULL,
        nickname varchar(255) NOT NULL,
        description varchar(255) NOT NULL,
        avatar_url varchar(255) NOT NULL,
        access_token text NOT NULL,
        access_secret varchar(255) NOT NULL,
        refresh_token varchar(255) NOT NULL,
        raw_data text DEFAULT NULL,
        expires_at timestamp NULL DEFAULT NULL,
        created_at timestamp NULL DEFAULT NULL,
        updated_at timestamp NULL DEFAULT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY connected_accounts_unique (user_id, provider_id, provider_user_id)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;