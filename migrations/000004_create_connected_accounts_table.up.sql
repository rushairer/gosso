create table
    connected_accounts (
        id bigint unsigned auto_increment primary key,
        user_id char(36) not null,
        provider varchar(255) not null,
        provider_user_id varchar(255) not null,
        name varchar(255) not null,
        email varchar(255) not null,
        phone varchar(255) not null,
        location varchar(255) not null,
        nickname varchar(255) not null,
        description varchar(255) not null,
        avatar_url varchar(255) not null,
        access_token text not null,
        access_secret varchar(255) not null,
        refresh_token varchar(255) not null,
        id_token text null,
        raw_data text null,
        expires_at timestamp null,
        created_at timestamp default current_timestamp() not null,
        updated_at timestamp default current_timestamp() not null on update current_timestamp(),
        constraint connected_accounts_unique unique (user_id, provider, provider_user_id)
    );