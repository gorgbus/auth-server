drop table users;

drop type if exists Account;

create type Account as (
    id varchar(20),
    avatar varchar(64),
    username varchar(32)
);

create table users (
    app_id uuid not null,
    user_id serial not null,
    discord Account,
    steam Account,
    primary key (app_id, user_id),
    constraint fk_app_id_user
        foreign key (app_id)
        references app (id)
)
