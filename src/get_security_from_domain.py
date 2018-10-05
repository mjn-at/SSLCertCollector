#!/usr/bin/env python

scriptname = "get_security_from_domain"

import sys
import time
import mysql.connector
import threading
from creds import mysql_user, mysql_password, mysql_host, mysql_database

from ssl import CertificateError
from sslyze.concurrent_scanner import ConcurrentScanner, PluginRaisedExceptionScanResult
from sslyze.plugins.certificate_info_plugin import CertificateInfoScanCommand
from sslyze.plugins.session_renegotiation_plugin import SessionRenegotiationScanCommand
from sslyze.server_connectivity_tester import ServerConnectivityTester, ServerConnectivityError
from sslyze.plugins.utils.certificate_utils import CertificateUtils
from sslyze.plugins.utils.trust_store.trust_store import TrustStore
from sslyze.plugins.utils.trust_store.trust_store import InvalidCertificateChainOrderError
from sslyze.plugins.utils.trust_store.trust_store import AnchorCertificateNotInTrustStoreError
from sslyze.plugins.utils.trust_store.trust_store_repository import TrustStoresRepository
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.plugins.openssl_cipher_suites_plugin import *
from sslyze.plugins.heartbleed_plugin import *
from sslyze.plugins.http_headers_plugin import *

supports_sslv2 = 0
supports_sslv3 = 0
supports_tlsv10 = 0
supports_tlsv11 = 0
supports_tlsv12 = 0
supports_tlsv13 = 0

ssl_version = ""

vulnerable_heartbleed = 0
hsts_supported = 0
hsts_preload_set = 0
hsts_include_subdomains_set = 0
hsts_max_age_set = 0
hpkp_supported = 0
chain_is_trusted = 0
cert_matches_hostname = 0
cert_is_ev = False

tbl_supported_ciphers = 'supported_ciphers'
tbl_ssl_options = 'ssl_options'
tbl_domainlist = 'base_domainlist'

class SSLyzeScanThread(threading.Thread):
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
    progress_indicator = 8750 # = total / no.threads / 10

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
            p = p + 10
            with open(workinglog, 'a') as worklog:
                worklog.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': ' + str(
                    p) + '% done, Working on dataset ' + str(i) + ' from ' + str(interval) + ' sets\n')

        sslyzeScan(threadname,connection,row[0]) # url

        i = i + 1

    connection.close()

def getIP(url):
    is_true = 0
    try:
        host_ip = socket.gethostbyname(url)
        is_true = 1
    except Exception:
        host_ip = '0.0.0.0'
    return is_true

def sslyzeScan(threadname,connection,url):

    logfile_connection = 'log/' + scriptname + '-error-connections.log'
    logfile_other = 'log/' + scriptname + '-error-other.log'
    logfile_scan = 'log/' + scriptname + '-error-other.log'

    has_ip = 0
    is_reachable = 0

    has_ip = getIP(url)

    if has_ip:
        try:
            server_tester = ServerConnectivityTester(hostname=url)
            server_info = server_tester.perform()
            is_reachable = 1
        except ServerConnectivityError:
            with open(logfile_connection, 'a') as log:
                log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not connect to host: '+url+'\n')
        except Exception:
            with open(logfile_other, 'a') as log:
                log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Thrown error for host: '+url+'\n')
    else:
        with open(logfile_connection, 'a') as log:
            log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not resolve host: ' + url + '\n')

    if (is_reachable):
        concurrent_scanner = ConcurrentScanner()
        concurrent_scanner.queue_scan_command(server_info, Sslv20ScanCommand())
        concurrent_scanner.queue_scan_command(server_info, Sslv30ScanCommand())
        concurrent_scanner.queue_scan_command(server_info, Tlsv10ScanCommand())
        concurrent_scanner.queue_scan_command(server_info, Tlsv11ScanCommand())
        concurrent_scanner.queue_scan_command(server_info, Tlsv12ScanCommand())
        concurrent_scanner.queue_scan_command(server_info, Tlsv13ScanCommand())
        concurrent_scanner.queue_scan_command(server_info, HeartbleedScanCommand())
        concurrent_scanner.queue_scan_command(server_info, HttpHeadersScanCommand())
        concurrent_scanner.queue_scan_command(server_info, CertificateInfoScanCommand())

        # Process the results
        for scan_result in concurrent_scanner.get_results():

            # Sometimes a scan command can unexpectedly fail (as a bug); it is returned as a PluginRaisedExceptionResult
            if isinstance(scan_result, PluginRaisedExceptionScanResult):
                with open(logfile_scan, 'a') as log:
                    log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Scan command failed: {}'.format(scan_result.as_text()) + '\n')

            if isinstance(scan_result.scan_command, Sslv20ScanCommand):
                ssl_version = "sslv2"
                try:
                    if len(scan_result.accepted_cipher_list) == 0:
                        supports_sslv2 = 0
                    else:
                        supports_sslv2 = 1
                        for cipher in scan_result.accepted_cipher_list:
                            cipher = (u'{}'.format(cipher.name))
                            sql_command = ('insert into '+ tbl_supported_ciphers +'(url,cipher,version) values (%s,%s,%s)')
                            sql_data = (url,cipher,ssl_version)
                            cur0 = connection.cursor()
                            cur0.execute(sql_command, sql_data)
                            connection.commit()
                            cur0.close()
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get sslv2 attributes for host: ' + url + '\n')
                    supports_sslv2 = 0

            if isinstance(scan_result.scan_command, Sslv30ScanCommand):
                ssl_version = "sslv3"
                try:
                    if len(scan_result.accepted_cipher_list) == 0:
                        supports_sslv3 = 0
                    else:
                        supports_sslv3 = 1
                        for cipher in scan_result.accepted_cipher_list:
                            cipher = (u'{}'.format(cipher.name))
                            sql_command = ('insert into '+ tbl_supported_ciphers +'(url,cipher,version) values (%s,%s,%s)')
                            sql_data = (url,cipher,ssl_version)
                            cur0 = connection.cursor()
                            cur0.execute(sql_command, sql_data)
                            connection.commit()
                            cur0.close()
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get sslv3 attributes for host: ' + url + '\n')
                    supports_sslv3 = 0

            if isinstance(scan_result.scan_command, Tlsv10ScanCommand):
                ssl_version = "tlsv10"
                try:
                    if len(scan_result.accepted_cipher_list) == 0:
                        supports_tlsv10 = 0
                    else:
                        supports_tlsv10 = 1
                        for cipher in scan_result.accepted_cipher_list:
                            cipher = (u'{}'.format(cipher.name))
                            sql_command = ('insert into '+ tbl_supported_ciphers +'(url,cipher,version) values (%s,%s,%s)')
                            sql_data = (url,cipher,ssl_version)
                            cur0 = connection.cursor()
                            cur0.execute(sql_command, sql_data)
                            connection.commit()
                            cur0.close()
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get tlsv10 attributes for host: ' + url + '\n')
                    supports_tlsv10 = 0

            if isinstance(scan_result.scan_command, Tlsv11ScanCommand):
                ssl_version = "tlsv11"
                try:
                    if len(scan_result.accepted_cipher_list) == 0:
                        supports_tlsv11 = 0
                    else:
                        supports_tlsv11 = 1
                        for cipher in scan_result.accepted_cipher_list:
                            cipher = (u'{}'.format(cipher.name))
                            sql_command = ('insert into '+ tbl_supported_ciphers +'(url,cipher,version) values (%s,%s,%s)')
                            sql_data = (url,cipher,ssl_version)
                            cur0 = connection.cursor()
                            cur0.execute(sql_command, sql_data)
                            connection.commit()
                            cur0.close()
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get tlsv11 attributes for host: ' + url + '\n')
                    supports_tlsv11 = 0

            if isinstance(scan_result.scan_command, Tlsv12ScanCommand):
                ssl_version = "tlsv12"
                try:
                    if len(scan_result.accepted_cipher_list) == 0:
                        supports_tlsv12 = 0
                    else:
                        supports_tlsv12 = 1
                        for cipher in scan_result.accepted_cipher_list:
                            cipher = (u'{}'.format(cipher.name))
                            sql_command = ('insert into '+ tbl_supported_ciphers +'(url,cipher,version) values (%s,%s,%s)')
                            sql_data = (url,cipher,ssl_version)
                            cur0 = connection.cursor()
                            cur0.execute(sql_command, sql_data)
                            connection.commit()
                            cur0.close()
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get tlsv12 attributes for host: ' + url + '\n')
                    supports_tlsv12 = 0

            if isinstance(scan_result.scan_command, Tlsv13ScanCommand):
                ssl_version = "tlsv13"
                try:
                    if len(scan_result.accepted_cipher_list) == 0:
                        supports_tlsv13 = 0
                    else:
                        supports_tlsv13 = 1
                        for cipher in scan_result.accepted_cipher_list:
                            cipher = (u'{}'.format(cipher.name))
                            sql_command = ('insert into '+ tbl_supported_ciphers +'(url,cipher,version) values (%s,%s,%s)')
                            sql_data = (url,cipher,ssl_version)
                            cur0 = connection.cursor()
                            cur0.execute(sql_command, sql_data)
                            connection.commit()
                            cur0.close()
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get tlsv13 attributes for host: ' + url + '\n')
                    supports_tlsv13 = 0

            if isinstance(scan_result.scan_command, HeartbleedScanCommand):
                vulnerable_heartbleed = 0
                try:
                    if (scan_result.is_vulnerable_to_heartbleed):
                        vulnerable_heartbleed = 1
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get heartbleed attribute for host: ' + url + '\n')
                    vulnerable_heartbleed = 0

            if isinstance(scan_result.scan_command, HttpHeadersScanCommand):
                hsts_preload_set = 0
                hsts_include_subdomains_set = 0
                hsts_max_age_set = 0
                hsts_supported = 0
                hpkp_supported = 0

                try:
                    if (scan_result.hsts_header):
                        hsts_supported = 1
                        if (scan_result.hsts_header.preload):
                            hsts_preload_set = 1
                        if (scan_result.hsts_header.include_subdomains) == True:
                            hsts_include_subdomains_set = 1
                        hsts_max_age_set = scan_result.hsts_header.max_age
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get hsts attributes for host: ' + url + '\n')
                    hsts_preload_set = 0
                    hsts_include_subdomains_set = 0
                    hsts_max_age_set = 0
                    hsts_supported = 0

                try:
                    if (scan_result.hpkp_header):
                        hpkp_supported = 1
                except AttributeError:
                    hpkp_supported = 0

            if isinstance(scan_result.scan_command, CertificateInfoScanCommand):
                chain_is_trusted = 0
                try:
                    if (scan_result.verified_certificate_chain):
                        chain_is_trusted = 1
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get hpkp attributes for host: ' + url + '\n')
                    chain_is_trusted = 0

                cert_matches_hostname = 0
                cert_is_ev = False
                try:
                    CertificateUtils.matches_hostname(scan_result.certificate_chain[0],server_info.tls_server_name_indication)
                    cert_matches_hostname = 1
                except CertificateError:
                    cert_matches_hostname = 0
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime(
                            "%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get certificate_chain attribute for host: ' + url + '\n')
                try:
                    cert_is_ev = TrustStoresRepository.get_default().get_main_store().is_extended_validation(
                        scan_result.certificate_chain[0])
                except AttributeError:
                    with open(logfile_scan, 'a') as log:
                        log.write('Error, ' + time.strftime(
                            "%Y-%m-%d %H:%M:%S") + ', ' + threadname + ': Could not get extended_validation attribute for host: ' + url + '\n')

        sql_cmd = ('insert into ' + tbl_ssl_options + '(url,heartbleed_vulnerable,hsts_supported,hsts_preload_set,hsts_include_subdomains_set,hsts_max_age_set,hpkp_supported,chain_is_trusted,match_hostname,is_ev,sslv2,sslv3,tlsv10,tlsv11,tlsv12,tlsv13) values (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)')
        sql_dat = (url,vulnerable_heartbleed,hsts_supported,hsts_preload_set,hsts_include_subdomains_set,hsts_max_age_set,hpkp_supported,chain_is_trusted,cert_matches_hostname,cert_is_ev,supports_sslv2,supports_sslv3,supports_tlsv10,supports_tlsv11,supports_tlsv12,supports_tlsv13)
        cur = connection.cursor()
        cur.execute(sql_cmd,sql_dat)
        connection.commit()
        cur.close()

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

    # initialize Logfile
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
    else:
        interval = number_domains / number_threads
        remnant = number_domains % number_threads
        stopindex = interval

        for x in range(number_threads):
            threadname = 'Thread-'+str(x)+''
            thread = SSLyzeScanThread(threadname, startindex, interval, tbl_domainlist, logfile)
            thread.start()
            startindex = startindex + interval
            stopindex = stopindex + interval
            time.sleep(5)

        # process the remaining dataset
        if stopindex >= number_domains:
            with open(logfile, 'a') as log:
                log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Start last thread with rows starting: ' + str(startindex) + ' with interval ' + str(remnant) + '\n');
            get_domainlist(threadname, startindex, remnant, tbl_domainlist)
        else:
            with open(logfile, 'a') as log:
                log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', All rows processed\n');

    with open(logfile, 'a') as log:
        log.write('Info, ' + time.strftime("%Y-%m-%d %H:%M:%S") + ', Program finished \n')

if __name__ == "__main__":
    main()
