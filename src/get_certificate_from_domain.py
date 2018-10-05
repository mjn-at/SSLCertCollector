#!/usr/bin/env python

scriptname = "get_certificate_from_domain"

import sys
import ssl
import OpenSSL
import time
import mysql.connector
import threading
from socket import *

from creds import mysql_user, mysql_password, mysql_host, mysql_database


logfile = ''
certfolder = ''
tbl_runversion = ''
tbl_domainlist = 'base_domainlist'

port = 443
setdefaulttimeout(5)

class CertificateFetchThread(threading.Thread):
    def __init__(self, threadname, startindex, stopindex, certfolder, tbl_runversion, logfile):
        threading.Thread.__init__(self)
	self.threadname = threadname
        self.startindex = startindex
        self.stopindex = stopindex
        self.certfolder = certfolder
        self.tbl_runversion = tbl_runversion
        self.logfile = logfile

    def run(self):
        with open(self.logfile, 'a') as log:
            log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Start thread ' + str(self.threadname) + ' with rows between: ' + str(self.startindex) + ' and ' + str(self.stopindex) + '\n');
        get_domainlist(self.threadname,self.startindex, self.stopindex, self.certfolder, self.tbl_runversion)
        with open(self.logfile, 'a') as log:
            log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Stop thread ' + str(self.threadname) + ' with rows between: ' + str(self.startindex) + ' and ' + str(self.stopindex) + '\n');


def getIP(host):
    try:
	host_ip = socket.gethostbyname(host)
    except Exception as e:
        host_ip = '0.0.0.0'
    return host_ip

def fetchCertificate(threadname,connection,id,url,certfolder,tbl_runversion):

    sslCertificate = ''
    ip = getIP(url)
    logfile = 'log/'+tbl_runversion+'.log'

    conn = connection

    try:
        sslCertificate = ssl.get_server_certificate((url, port))
    except (error,timeout) as e:
        with open(logfile, 'a') as log:
            log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + str(id) + ',' + str(url) + ',' + str(ip) + ',Port 443 active but no ssl-certificate retrieved\n')

    if len(sslCertificate) > 0:
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, sslCertificate)
        serial = str(x509.get_serial_number())
        cert = sslCertificate
        stmt_insert = ('insert into ' + tbl_runversion + ' (id,url,ip,serial) values (%s,%s,%s,%s)')
        stmt_data = (id,url,ip,serial)

        cur = conn.cursor()
        cur.execute(stmt_insert,stmt_data)
        conn.commit()
        cur.close()

        # write cert to file, use domain-name as file-name, because some has same fingerprint (i.e. self-signed-certs)
        with open(certfolder + '%s.crt' % str(url), 'wb') as certfile:
            certfile.write(sslCertificate)

def get_domainlist(threadname,start,stop,certfolder,tbl_runversion):

    try:
        connection = mysql.connector.connect(user=mysql_user, password=mysql_password, host=mysql_host,database=mysql_database,connection_timeout=1000)
    except Exception as err:
        print 'sub get_domainlist: Problem connecting to db\n'
        exit(2)

    cursor = connection.cursor()
    cursor.execute('select id, url from ' + str(tbl_domainlist) + ' where id between ' + str(start) + ' and ' + str(stop) + ' ');
    domains_to_query = cursor.fetchall()
    cursor.close()

    for row in domains_to_query:
        fetchCertificate(threadname,connection,row[0],row[1],certfolder,tbl_runversion) # id, url

    connection.close()

def main():

    number_threads = 1
    startindex = 1
    stopindex = 1
    interval = 0
    connection = ''

    # get parameters
    if len(sys.argv) < 3:
        print 'ERROR: Script need Run-Version and Number of Threads to run\n'
        print 'Example: program.py 04 32\n'
        exit(0)
    else:
        run_version = sys.argv[1]  # @TODO: add zerofill-option
        number_threads = int(sys.argv[2])

    # correct the variables

    run_version_string = 'run_' + str(run_version) + ''
    logfile = 'log/get_certificates_'+run_version_string+'.log'
    certfolder = 'certs/'+run_version_string+'/'
    tbl_runversion = run_version_string

    # initialize Logfile
    with open(logfile, 'a') as log:
        log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Program started initiating run-version ' + str(run_version) + ' with ' + str(number_threads) + ' threads \n')

    # get number of lines in domainlist
    try:
        connection = mysql.connector.connect(user=mysql_user, password=mysql_password, host=mysql_host,database=mysql_database)
    except Exception as err:
        print 'Problem connecting to db\n'
        exit(2)

    cursor = connection.cursor()
    cursor.execute('select count(*) from ' + str(tbl_domainlist) + '')
    result_array = cursor.fetchone()
    number_domains = result_array[0]

    with open(logfile, 'a') as log:
        log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Number of Domains to check: ' + str(number_domains) + '\n')

    cursor.close()
    connection.close()

    stopindex = number_domains

    if number_domains < number_threads:
        with open(logfile, 'a') as log:
            log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Start single thread with rows between: ' + str(startindex) + ' and ' + str(stopindex) + '\n');
        # number threads is greater than rows, so only use single-thread
        get_domainlist(startindex, stopindex, certfolder, tbl_runversion)
    else:
        interval = number_domains / number_threads
        remnant = number_domains % number_threads
        stopindex = interval

        for x in range(number_threads):
            threadname = 'Thread-'+str(x)+''
            thread = CertificateFetchThread(threadname, startindex, stopindex, certfolder, tbl_runversion, logfile)
            thread.start()
            startindex = startindex + interval
            stopindex = stopindex + interval
            time.sleep(5)

        # process the remaining dataset
        if stopindex >= number_domains:
            stopindex = number_domains
            with open(logfile, 'a') as log:
                log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Start last thread with rows between: ' + str(startindex) + ' and ' + str(stopindex) + '\n');
            get_domainlist(threadname, startindex, stopindex, certfolder, tbl_runversion)
        else:
            with open(logfile, 'a') as log:
                log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', All rows processed\n');

    with open(logfile, 'a') as log:
        log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Program finished initiating run-version ' + str(run_version) + '\n')

if __name__ == "__main__":
    main()
