alter table users
add column steam_id varchar(20),
add column google_id varchar(256);

alter table users
add constraint unique_ids
unique (discord_id, steam_id, google_id);
