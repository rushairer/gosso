create table
    socialite_providers (
        id bigint unsigned auto_increment primary key,
        name varchar(255) not null,
        provider varchar(255) not null,
        status tinyint default 0 not null,
        config text null,
        deleted_at timestamp null,
        created_at timestamp default current_timestamp() not null,
        updated_at timestamp default current_timestamp() not null on update current_timestamp()
    );