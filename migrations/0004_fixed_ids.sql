alter table users
drop constraint unique_ids;

alter table users
add constraint discord_id_unique
unique (discord_id, app_id);

alter table users
add constraint steam_id_unique 
unique (steam_id, app_id);

alter table users
add constraint google_id_unqiue 
unique (google_id, app_id);
