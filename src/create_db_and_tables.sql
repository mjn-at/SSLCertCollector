####
#
# File: create_db_and_tables.sql
# Description: Creates Database and Tables used for statistics about SSL-/TLS-Servers and Certificates
# Version: 001
# Date: 2018-05-07
# Author: Martin Nagel
#
####


# create database
create database sslcerts;
use sslcerts;

# create user, set password and privileges
grant usage on sslcerts.* to 'db_user'@'localhost' identified by 'db_password' with max_queries_per_hour 0 max_connections_per_hour 0 max_updates_per_hour 0; 
grant select, insert, update, delete, lock tables on sslcerts.* to 'db_user'@'localhost' identified by 'db_password';
flush privileges;

# change param "max_connections". The scripts create many connections through threading.
# default value is 151 (show variables like "max_connections")
set global max_connections = 1000;

# create tables 

# table-name:  base_domainlist
# description: holds the domainlist which should be evaluated
CREATE TABLE `sslcerts`.`base_domainlist` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `url` VARCHAR(255) NOT NULL, 
  PRIMARY KEY (`id`));

# table-name:  run_0x (run_01, run_02,...)
# description: tables for collected certificates. create one for each run
CREATE TABLE `sslcerts`.`run_01` (
  `id` INT NOT NULL AUTO_INCREMENT, 
  `url` VARCHAR(255) NOT NULL, 
  `ip` VARCHAR(255), 
  `serial` TEXT, 
  PRIMARY KEY (`id`));

# table-name:  certDetails_run_0x (run_01, run_02,...)
# description: tables for details of collected certificates. create one for each run
CREATE TABLE `sslcerts`.`certDetails_run_01` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `url` VARCHAR(255) NULL,
  `subject_cn` VARCHAR(1000) NULL,
  `subject_cn_c` VARCHAR(255) NULL,
  `subject_cn_st` VARCHAR(255) NULL,
  `subject_cn_l` VARCHAR(255) NULL,
  `subject_cn_o` VARCHAR(255) NULL,
  `subject_cn_ou` VARCHAR(255) NULL,
  `subject_cn_cn` VARCHAR(255) NULL,
  `subject_cn_mail` VARCHAR(255) NULL,
  `serial` VARCHAR(255) NULL,
  `issuer_cn` VARCHAR(1000) NULL,
  `issuer_cn_c` VARCHAR(255) NULL,
  `issuer_cn_st` VARCHAR(255) NULL,
  `issuer_cn_l` VARCHAR(255) NULL,
  `issuer_cn_o` VARCHAR(255) NULL,
  `issuer_cn_ou` VARCHAR(255) NULL,
  `issuer_cn_cn` VARCHAR(255) NULL,
  `issuer_cn_mail` VARCHAR(255) NULL,
  `not_after` VARCHAR(255) NULL,
  `not_before` VARCHAR(255) NULL,
  `has_expire` VARCHAR(255) NULL,
  `has_valid_dns` VARCHAR(255) NULL,
  `version` VARCHAR(255) NULL,
  `signature_algorithm` VARCHAR(255) NULL,
  `duration` VARCHAR(255) NULL,
  PRIMARY KEY (`id`));
ALTER TABLE certDetails_run_01 CONVERT TO CHARACTER SET utf8;
  
# table-name: caa_records
# description: table for results of DNS-CAA-Queries 
CREATE TABLE `sslcerts`.`caa_records` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `url` VARCHAR(255) NULL,
  `issue` VARCHAR(255) NULL,
  `issuewild` VARCHAR(255) NULL,
  `iodef` VARCHAR(255) NULL,
  PRIMARY KEY (`id`));

# table-name: supported_ciphers
# description: table for results of the scans from python-script with sslyze-library
CREATE TABLE `sslcerts`.`supported_ciphers` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `url` VARCHAR(255) NULL,
  `cipher` VARCHAR(255) NULL,
  `version` VARCHAR(20) NULL,
  PRIMARY KEY (`id`));

# table-name: ssl_options
# description: table for results of the scans from python-script with sslyze-library
CREATE TABLE `sslcerts`.`ssl_options` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `url` VARCHAR(255) NULL,
  `heartbleed_vulnerable` int NULL,
  `hsts_supported` int NULL,
  `hsts_preload_set` int NULL,
  `hsts_include_subdomains_set` int NULL,
  `hsts_max_age_set` int NULL,
  `hpkp_supported` int NULL,
  `chain_is_trusted` int NULL,
  `match_hostname` int NULL,
  `is_ev` int NULL,
  `sslv2` int NULL,
  `sslv3` int NULL,
  `tlsv10` int NULL,
  `tlsv11` int NULL,
  `tlsv12` int NULL,
  `tlsv13` int NULL,
  PRIMARY KEY (`id`));

# import domainlist-data from file
load data local infile 'data/domainlist.txt' into table base_domainlist lines terminated by '\n' (url);

