create table app (
    id uuid primary key default uuid_generate_v4(),
    name varchar(32) not null
);

create table redirect_uri (
    id serial not null,
    app_id uuid not null,
    uri varchar(256) not null,
    primary key (id, app_id),
    constraint fk_app_id_uri
        foreign key (app_id)
        references app (id)
);

create table users (
    app_id uuid not null,
    discord_id varchar(20),
    primary key (app_id, discord_id),
    constraint fk_app_id_user
        foreign key (app_id)
        references app (id)
);
