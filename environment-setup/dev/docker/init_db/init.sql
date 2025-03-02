create database app_db;
create user app_user with password 'app_user_pw';
alter database app_db owner to app_user;
