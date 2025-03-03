create database app_db;
create user app_user with password 'app_user_pw';
alter database app_db owner to app_user;

create database sso_db;
create user sso_user with password 'sso_user_pw';
alter database sso_db owner to sso_user;
