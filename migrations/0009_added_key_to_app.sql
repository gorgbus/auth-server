create extension if not exists pgcrypto;

alter table app
add column private_key text not null,
add column public_key text not null;
