CREATE TABLE
    IF NOT EXISTS user_details (
        id char(36) NOT NULL,
        nickname varchar(255) NOT NULL,
        avatar_url varchar(255) DEFAULT NULL,
        description varchar(255) DEFAULT NULL,
        location varchar(255) DEFAULT NULL,
        created_at timestamp NOT NULL,
        updated_at timestamp NOT NULL,
        PRIMARY KEY (id)
    ) ENGINE = InnoDB DEFAULT CHARSET = utf8mb4 COLLATE = utf8mb4_unicode_ci;