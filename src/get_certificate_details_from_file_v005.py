#!/usr/bin/env python

scriptname = "get_certificate_details_from_file_v005"

import sys
import time
import mysql.connector
import threading
from creds import mysql_user, mysql_password, mysql_host, mysql_database
import OpenSSL
from unidecode import unidecode

logfile = ''
progress_indicator = 5000
error_counter = 0

class GetCertThread(threading.Thread):
    def __init__(self, threadname, startindex, interval, dbtable, logfile):
        threading.Thread.__init__(self)
        self.threadname = threadname
        self.startindex = startindex
        self.interval = interval
        self.dbtable = dbtable
        self.logfile = logfile

    def run(self):
        with open(self.logfile, 'a') as log:
            log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Start thread ' + str(self.threadname) + ' with rows starting: ' + str(self.startindex) + ' with interval ' + str(self.interval) + '\n');
        get_domainlist(self.threadname,self.startindex, self.interval, self.dbtable)
        with open(self.logfile, 'a') as log:
            log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Stop thread ' + str(self.threadname) + ' with rows starting: ' + str(self.startindex) + ' with interval ' + str(self.interval) + '\n');

def remove_non_ascii(text):
    return unidecode(unicode(text, encoding = "utf-8"))
#    return unidecode(unicode(text, encoding = "latin-1"))

def get_domainlist(threadname,start,interval,dbtable):

    workinglog = 'log/' + scriptname + '_' + str(dbtable) +'-working.log'

    try:
        connection = mysql.connector.connect(user=mysql_user, password=mysql_password, host=mysql_host,database=mysql_database,connection_timeout=1000)
    except Exception as err:
        print 'sub get_domainlist: Problem connecting to db\n'
        exit(2)

    cursor = connection.cursor()
    cursor.execute('select url from ' + str(dbtable) + ' limit ' + str(start) + ',' + str(interval) + ' ')
    certfiles_to_check = cursor.fetchall()
    cursor.close()

    i = 1
    p = 0
    for domain in certfiles_to_check:
        if i % progress_indicator == 0:
            p = p+10
            with open(workinglog, 'a') as worklog:
                worklog.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': ' + str(p) +'% done, Working on dataset ' + str(i) + ' from ' + str(interval) + ' sets\n')
        getCertDetails(threadname,connection,domain[0],dbtable)
        i = i+1

    connection.close()

def getCertDetails(threadname,connection,domain,runversion):

    logfile = 'log/' + scriptname + '_' + runversion + '.log'
    tbl_certDetails_runversion = 'certDetails_' + runversion
    certfolder = '/home/martin/Documents/BScProject/certs'
    certfile = certfolder + '/' + str(runversion) + '/' + str(domain) + '.crt'
    can_read_certfile = 0

    subject_cn = ''
    subject_cn_c = ''
    subject_cn_st = ''
    subject_cn_l = ''
    subject_cn_o = ''
    subject_cn_ou = ''
    subject_cn_cn = ''
    subject_cn_mail = ''
    serial = ''
    issuer_cn = ''
    issuer_cn_c = ''
    issuer_cn_st = ''
    issuer_cn_l = ''
    issuer_cn_o = ''
    issuer_cn_ou = ''
    issuer_cn_cn = ''
    issuer_cn_mail = ''
    not_after = ''
    not_before = ''
    has_expire = ''
    has_valid_dns = 'dns_missing'
    version = ''
    signature_algorithm = ''
    duration = ''

    offset = 0
    if runversion == "run_01":
        offset = 20171123000000
    elif runversion == "run_02":
        offset = 20171227000000
    elif runversion == "run_03":
        offset = 20180127000000
    elif runversion == "run_04":
        offset = 20180228000000
    elif runversion == "run_05":
        offset = 20180409000000
    elif runversion == "run_06":
        offset = 20180428000000

    try:
        with open(certfile, "r") as my_cert_file:
            my_cert_text = my_cert_file.read()
            x509Certificate = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, my_cert_text)
        can_read_certfile = 1
    except:
        with open(logfile, 'a') as log:
            log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + str(threadname) + ': Could not open Certfile: ' + str(certfile) +' for domain: ' + str(domain) + '\n')

    if can_read_certfile == 1:
        subject_cn = str(x509Certificate.get_subject().get_components())
        serial = str(x509Certificate.get_serial_number())
        issuer_cn = str(x509Certificate.get_issuer().get_components())
        not_after = str(x509Certificate.get_notAfter())
        not_before = str(x509Certificate.get_notBefore())
        try:
            has_expire = str(x509Certificate.has_expired())
        except:
            has_expire = 'Other'
            with open(logfile, 'a') as log:
                log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + str(threadname) + ': Problem calculating expire-time for Certfile: ' + str(certfile) + ' for domain: ' + str(domain) + '\n')

        if has_expire == "True":
            if offset >= int(not_before[:-1]):
                if offset < int(not_after[:-1]):
                    has_expire = "False"
                    with open(logfile, 'a') as log:
                        log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + str(threadname) + ': Cert is valid between not_before: '+ str(not_before) + ' and not_after: ' + str(not_after) + ' for Certfile: ' + str(certfile) + '. offset: ' + str(offset) + '\n')

        version =  str(x509Certificate.get_version())
        signature_algorithm = str(x509Certificate.get_signature_algorithm())

        x = 0
        subject_components = x509Certificate.get_subject().get_components()
        while x < len(subject_components):
            if "C" == subject_components[x][0]:
                subject_cn_c = subject_components[x][1]
            elif "ST" == subject_components[x][0]:
                subject_cn_st = subject_components[x][1]
            elif "L" == subject_components[x][0]:
                subject_cn_l = subject_components[x][1]
            elif "O" == subject_components[x][0]:
                subject_cn_o = subject_components[x][1]
            elif "OU" == subject_components[x][0]:
                subject_cn_ou = subject_components[x][1]
            elif "CN" == subject_components[x][0]:
                subject_cn_cn = subject_components[x][1]
            elif "emailAddress" == subject_components[x][0]:
                subject_cn_mail = subject_components[x][1]
            x = x+1

        y = 0
        issuer_components = x509Certificate.get_issuer().get_components()
        while y < len(issuer_components):
            if "C" == issuer_components[y][0]:
                issuer_cn_c = issuer_components[y][1]
            elif "ST" == issuer_components[y][0]:
                issuer_cn_st = issuer_components[y][1]
            elif "L" == issuer_components[y][0]:
                issuer_cn_l = issuer_components[y][1]
            elif "O" == issuer_components[y][0]:
                issuer_cn_o = issuer_components[y][1]
            elif "OU" == issuer_components[y][0]:
                issuer_cn_ou = issuer_components[y][1]
            elif "CN" == issuer_components[y][0]:
                issuer_cn_cn = issuer_components[y][1]
            elif "emailAddress" == issuer_components[y][0]:
                issuer_cn_mail = issuer_components[y][1]
            y = y+1

        z = 0
        if z == x509Certificate.get_extension_count():
            has_valid_dns = 'extension_empty'

        wildcard = "*" + domain[3:]
        try:
            while z < x509Certificate.get_extension_count():
                if "DNS:" in str(x509Certificate.get_extension(z)):
                    san = str(x509Certificate.get_extension(z))
                    if domain in san:
                        has_valid_dns = 'host'
                    elif wildcard in san:
                        has_valid_dns = 'wildcard'
                    elif domain[4:] in san:
                        has_valid_dns = 'domain'
                    else:
                        has_valid_dns = 'no_match'
                z = z+1
        except:
            has_valid_dns = 'not_readable'
            with open(logfile, 'a') as log:
                log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + str(threadname) + ': Could not get Extensions from Certfile: ' + str(certfile) + ' for domain: ' + str(domain) + '\n')

        i_duration = int(not_after[:-7])-int(not_before[:-7])

        years = i_duration / 10000
        m_duration = i_duration%10000

        if m_duration == 89:
            m_duration = 1
        elif m_duration == 90:
            m_duration = 2
        elif m_duration == 91:
            m_duration = 3
        elif m_duration == 92:
            m_duration = 4
        elif m_duration == 93:
            m_duration = 5
        elif m_duration == 94:
            m_duration = 6
        elif m_duration == 95:
            m_duration = 7
        elif m_duration == 96:
            m_duration = 8
        elif m_duration == 97:
            m_duration = 9
        elif m_duration == 98:
            m_duration = 10
        elif m_duration == 99:
            m_duration = 11

        duration = str(m_duration+(years*12))

        sql_command = ('insert into ' + tbl_certDetails_runversion + '(url,subject_cn, subject_cn_c, subject_cn_st, subject_cn_l, subject_cn_o, subject_cn_ou, subject_cn_cn, subject_cn_mail, serial, issuer_cn, issuer_cn_c, issuer_cn_st, issuer_cn_l, issuer_cn_o, issuer_cn_ou, issuer_cn_cn, issuer_cn_mail, not_after, not_before, has_expire, has_valid_dns, version, signature_algorithm, duration) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)')
        sql_data = (domain, subject_cn, subject_cn_c, subject_cn_st, subject_cn_l, subject_cn_o, subject_cn_ou, subject_cn_cn, subject_cn_mail, serial, issuer_cn, issuer_cn_c, issuer_cn_st, issuer_cn_l, issuer_cn_o, issuer_cn_ou, issuer_cn_cn, issuer_cn_mail, not_after, not_before, has_expire, has_valid_dns, version, signature_algorithm, duration)
        cur0 = connection.cursor()
        try:
            cur0.execute(sql_command, sql_data)
            connection.commit()
        except:
            issuer_cn_mail = issuer_cn_mail.decode('cp1250')
            issuer_cn_cn = issuer_cn_cn.decode('cp1250')
            issuer_cn_ou = issuer_cn_ou.decode('cp1250')
            issuer_cn_o = issuer_cn_o.decode('cp1250')
            issuer_cn_l = issuer_cn_l.decode('cp1250')
            issuer_cn_st = issuer_cn_st.decode('cp1250')
            issuer_cn_c = issuer_cn_c.decode('cp1250')
            subject_cn_mail = subject_cn_mail.decode('cp1250')
            subject_cn_o = subject_cn_o.decode('cp1250')
            subject_cn_cn = subject_cn_cn.decode('cp1250')
            subject_cn_ou = subject_cn_ou.decode('cp1250')
            subject_cn_st = subject_cn_st.decode('cp1250')
            subject_cn_c = subject_cn_c.decode('cp1250')
            subject_cn_l = subject_cn_l.decode('cp1250')
            subject_cn = subject_cn.decode('cp1250')
            issuer_cn = issuer_cn.decode('cp1250')

            sql_command = ('insert into ' + tbl_certDetails_runversion + '(url,subject_cn, subject_cn_c, subject_cn_st, subject_cn_l, subject_cn_o, subject_cn_ou, subject_cn_cn, subject_cn_mail, serial, issuer_cn, issuer_cn_c, issuer_cn_st, issuer_cn_l, issuer_cn_o, issuer_cn_ou, issuer_cn_cn, issuer_cn_mail, not_after, not_before, has_expire, has_valid_dns, version, signature_algorithm, duration) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)')
            sql_data = (domain, subject_cn, subject_cn_c, subject_cn_st, subject_cn_l, subject_cn_o, subject_cn_ou, subject_cn_cn, subject_cn_mail, serial, issuer_cn, issuer_cn_c, issuer_cn_st, issuer_cn_l, issuer_cn_o, issuer_cn_ou, issuer_cn_cn, issuer_cn_mail, not_after, not_before, has_expire, has_valid_dns, version, signature_algorithm, duration)
            try:
                cur0.execute(sql_command, sql_data)
                connection.commit()
            except:
                with open(logfile, 'a') as log:
                    log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + str(threadname) + ': Could not write Data into Database from Certfile: ' + str(certfile) + ' for domain: ' + str(domain) + '\n')
                    log.write('Error-Data, ' + str(sql_data) + '\n')

        cur0.close()

def main():

    number_threads = 1
    startindex = 0
    stopindex = 1
    interval = 0
    connection = ''

    # get parameters
    if len(sys.argv) < 3:
        print 'ERROR: Script need the RunVersion to process and Number of Threads to run\n'
        print 'Example: program.py 04 32\n'
        exit(0)
    else:
        run_version = sys.argv[1]
        number_threads = int(sys.argv[2])

    runversionstring = 'run_' + str(run_version) + ''
    logfile = 'log/' + scriptname + '_' + runversionstring + '.log'
    tbl_runversion = runversionstring

    # initialize Logfile
    with open(logfile, 'a') as log:
        log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Program started \n')

    try:
        connection = mysql.connector.connect(user=mysql_user, password=mysql_password, host=mysql_host,database=mysql_database)
    except Exception as err:
        print 'Problem connecting to db\n'
        exit(2)

    cursor = connection.cursor()
    cursor.execute('select count(*) from ' + str(tbl_runversion) + '')
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
        get_domainlist('Thread-0', startindex, number_domains, tbl_runversion)
    else:
        interval = number_domains / number_threads
        remnant = number_domains % number_threads
        stopindex = interval

        for x in range(number_threads):
            threadname = 'Thread-'+str(x)+''
            thread = GetCertThread(threadname, startindex, interval, tbl_runversion, logfile)
            thread.start()
            startindex = startindex + interval
            stopindex = stopindex + interval
            time.sleep(1)

        # process the remaining dataset
        if stopindex >= number_domains:
            with open(logfile, 'a') as log:
                log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Start last thread with rows starting: ' + str(startindex) + ' with interval ' + str(remnant) + '\n');
            threadname = 'Thread-Zero'
            get_domainlist(threadname, startindex, remnant, tbl_runversion)
        else:
            with open(logfile, 'a') as log:
                log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', All rows processed\n');

    with open(logfile, 'a') as log:
        log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Program finished \n')

if __name__ == "__main__":
    main()

