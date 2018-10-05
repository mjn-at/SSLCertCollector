SSLCertCollector
----------------


SSLCertCollector is a collection of scripts to download SSL-Certificates from webservers, extract and stores the data in a database.
It is used to compare SSL Certifictes over a longer period of time.
The scripts use the [sslyze](https://github.com/nabla-c0d3/sslyze) and OpenSSL library.

The scripts are used in the following way:

**create_db_and_tables.sql**
creates the database used for the scripts

**get_certificate_from_domain.py**
Downloads the certificates from the webservers (given list) and saves them to the disk.

**get_certificate_details_from_file.py**
extracts the data from the downloaded certificates and saves them to the database

**get_security_from_domain.py**
Checks the ssl/tls configuration from the webserver (uses sslyze) and saves the data to the database

**get_caa_for_domain.py**
checks for CAA (certificate authority authorization) entries in DNS


