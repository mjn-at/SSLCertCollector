
#!/usr/bin/env python

scriptname = "get_dns_info_for_domain"

import sys
import time
import mysql.connector
import threading
from creds import mysql_user, mysql_password, mysql_host, mysql_database
import dns.resolver

logfile = ''
tbl_domainlist = 'base_domainlist'
tbl_caa_records = 'caa_records'
progress_indicator = 1

class ScanThread(threading.Thread):
    def __init__(self, threadname, startindex, interval, tbl_domainlist, logfile):
        threading.Thread.__init__(self)
        self.threadname = threadname
        self.startindex = startindex
        self.interval = interval
        self.tbl_domainlist = tbl_domainlist
        self.logfile = logfile

    def run(self):
        with open(self.logfile, 'a') as log:
            log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Start thread ' + str(self.threadname) + ' with rows starting: ' + str(self.startindex) + ' with interval ' + str(self.interval) + '\n');
        get_domainlist(self.threadname,self.startindex, self.interval, self.tbl_domainlist)
        with open(self.logfile, 'a') as log:
            log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Stop thread ' + str(self.threadname) + ' with rows starting: ' + str(self.startindex) + ' with interval ' + str(self.interval) + '\n');

def get_domainlist(threadname,start,interval,tbl_domainlist):

    workinglog = 'log/' + scriptname + '-working.log'

    try:
        connection = mysql.connector.connect(user=mysql_user, password=mysql_password, host=mysql_host,database=mysql_database,connection_timeout=1000)
    except Exception as err:
        print 'sub get_domainlist: Problem connecting to db\n'
        exit(2)

    cursor = connection.cursor()
    cursor.execute('select url from ' + str(tbl_domainlist) + ' limit ' + str(start) + ',' + str(interval) + ' ')
    domains_to_query = cursor.fetchall()
    cursor.close()

    i = 1
    p = 0
    for row in domains_to_query:
        if i % progress_indicator == 0:
            p = p+10
            with open(workinglog, 'a') as worklog:
                worklog.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': ' + str(p) +'% done, Working on dataset ' + str(i) + ' from ' + str(interval) + ' sets\n')
        domain = row[0][4:] # url without "www."
        getCAAEntry(threadname,connection,domain)
        i = i+1

    connection.close()

def getCAAEntry(threadname,connection,domain):

    logfile = 'log/' + scriptname + '.log'
    hasCAA = 0
    issue = ''
    issuewild = ''
    iodef = ''
    caarecords = ''

    try:
        resolver = dns.resolver.Resolver(configure=False)
        caarecords = dns.resolver.query(domain, 'CAA')
        hasCAA = 1
        with open(logfile, 'a') as log:
            log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': CAA record found for domain: '+domain+'\n')
    except:
        with open(logfile, 'a') as log:
            log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': No CAA record set for domain: '+domain+'\n')

    if hasCAA == 1:
        print "\n###\n domain: " + domain
        for record in caarecords:
            if " issue " in str(record):
                x1,x2,x3 = str(record).split(" ")
                y1,issue,y2 = x3.split('"')
            elif " issuewild " in str(record):
                x1,x2,x3 = str(record).split(" ")
                y1,issuewild,y2 = x3.split('"')
            elif " iodef " in str(record):
                x1,x2,x3 = str(record).split(" ")
                y1,iodef,y2 = x3.split('"')

        sql_command = ('insert into ' + tbl_caa_records + '(url,issue,issuewild,iodef) values (%s,%s,%s,%s)')
        sql_data = (domain, issue, issuewild, iodef)
        cur0 = connection.cursor()
        cur0.execute(sql_command, sql_data)
        connection.commit()
        cur0.close()

def main():

    number_threads = 1
    startindex = 0
    stopindex = 1
    interval = 0
    connection = ''

    # get parameters
    if len(sys.argv) < 2:
        print 'ERROR: Script need Number of Threads to run\n'
        print 'Example: program.py 32\n'
        exit(0)
    else:
        number_threads = int(sys.argv[1])

    logfile = 'log/' + scriptname + '.log'

    with open(logfile, 'a') as log:
        log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Program started \n')

    try:
        connection = mysql.connector.connect(user=mysql_user, password=mysql_password, host=mysql_host,database=mysql_database)
    except Exception as err:
        print 'Problem connecting to db\n'
        exit(2)

    cursor = connection.cursor()
    cursor.execute('select count(*) from ' + str(tbl_domainlist) + '')
    result_array = cursor.fetchone()
    number_domains = result_array[0]
    cursor.close()
    connection.close()

    with open(logfile, 'a') as log:
        log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Number of Domains to check: ' + str(number_domains) + '\n')

    if number_domains < number_threads:
        with open(logfile, 'a') as log:
            log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Start single thread with rows starting: ' + str(startindex) + ' with interval ' + str(number_domains) + '\n');
        # number threads is greater than rows, so only use single-thread
        get_domainlist('Thread-0', startindex, number_domains, tbl_domainlist)
        progress_indicator = number_domains / 100
    else:
        interval = number_domains / number_threads
        remnant = number_domains % number_threads
        stopindex = interval
        progress_indicator = interval / 100

        for x in range(number_threads):
            threadname = 'Thread-'+str(x)+''
            thread = ScanThread(threadname, startindex, interval, tbl_domainlist, logfile)
            thread.start()
            startindex = startindex + interval
            stopindex = stopindex + interval
            time.sleep(5)

        # process the remaining dataset
        if stopindex >= number_domains:
            with open(logfile, 'a') as log:
                log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Start last thread with rows starting: ' + str(startindex) + ' with interval ' + str(remnant) + '\n');
            threadname = 'Thread-Zero'
            get_domainlist(threadname, startindex, remnant, tbl_domainlist)
        else:
            with open(logfile, 'a') as log:
                log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', All rows processed\n');

    with open(logfile, 'a') as log:
        log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Program finished \n')

if __name__ == "__main__":
    main()
