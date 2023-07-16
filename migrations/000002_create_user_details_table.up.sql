create table
    user_details (
        id char(36) not null primary key,
        nickname varchar(255) not null,
        avatar_url varchar(255) null,
        description varchar(255) null,
        location varchar(255) null,
        created_at timestamp default current_timestamp() not null,
        updated_at timestamp default current_timestamp() not null on update current_timestamp()
    );