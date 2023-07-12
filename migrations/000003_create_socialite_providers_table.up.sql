CREATE TABLE
    IF NOT EXISTS socialite_providers (
        id bigint (20) unsigned NOT NULL AUTO_INCREMENT,
        name varchar(255) NOT NULL,
        provider varchar(255) NOT NULL,
        config text DEFAULT NULL,
        created_at timestamp NULL DEFAULT NULL,
        updated_at timestamp NULL DEFAULT NULL,
        PRIMARY KEY (id)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;