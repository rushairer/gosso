create table
    users (
        id char(36) default uuid () not null primary key,
        connected_account_id bigint unsigned null,
        name varchar(255) not null,
        password varchar(255) null,
        email varchar(255) null,
        phone varchar(64) null,
        verified_at timestamp null,
        deleted_at timestamp null,
        created_at timestamp default current_timestamp() not null,
        updated_at timestamp default current_timestamp() not null on update current_timestamp(),
        constraint users_name_unique unique (name)
    );