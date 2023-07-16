create table
    oauth_clients (
        id char(36) not null primary key,
        name varchar(255) null,
        secret varchar(255) not null,
        callback text not null,
        created_at timestamp default current_timestamp() not null,
        updated_at timestamp default current_timestamp() not null on update current_timestamp()
    );