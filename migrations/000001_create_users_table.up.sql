CREATE TABLE
    IF NOT EXISTS users (
        id char(36) NOT NULL,
        connected_account_id bigint (20) unsigned DEFAULT NULL,
        name varchar(255) NOT NULL,
        password varchar(255) NULL DEFAULT NULL,
        email varchar(255) NULL DEFAULT NULL,
        phone varchar(64) NULL DEFAULT NULL,
        verified_at timestamp NULL DEFAULT NULL,
        deleted_at timestamp NULL DEFAULT NULL,
        created_at timestamp NOT NULL,
        updated_at timestamp NOT NULL,
        PRIMARY KEY (id),
        UNIQUE KEY users_name_unique (name)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;