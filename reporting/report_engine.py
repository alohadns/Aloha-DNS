#!/usr/bin/python


import MySQLdb, os, sys, time, datetime, collections
sys.path.append('/usr/local/alohadns/lib')
from counter import Counter
import locale
import email_report
import tldextract 
import smtplib, os
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders

ip_list_file = "/var/lib/alohadns/data/iplist.txt"
threat_list_folder = "/usr/local/alohadns/lib/threat_lists/"

threat_file_list = email_report.read_threat_files_list(threat_list_folder)

con = None

try:
        con = MySQLdb.connect('IP.OF.LOG.SERVER', 'SQLUSER', 'SQLPASS', 'DBNAME');

except MySQLdb.Error, e:
        print "Error %d: %s" % (e.args[0],e.args[1])
        sys.exit(1)

cur = con.cursor()
ip_list_obj = [line.strip() for line in open( ip_list_file )]
for item in ip_list_obj:
  print "LOOPSTART IP: " + item.split( )[0]
	client_ip = item.split( )[0]
	client_list_type = item.split( )[1]
	client_email = item.split( )[2]
	try:
		client_list_modified = item.split( )[3]
	except:
		client_list_modified = "NULL"

	today = datetime.date.today()
	yesterday = datetime.timedelta(days=-1) + today
	stop_date = str(today) + " 00:00:00"
	start_date = str(yesterday) + " 00:00:00"	

	deny_q = "SELECT * FROM log WHERE ip_address = '" + client_ip + "' AND disposition = 'deny' AND timestamp < '" + stop_date + "' AND timestamp > '" + start_date + "'"  
	allow_q = "SELECT * FROM log WHERE ip_address = '" + client_ip + "' AND disposition = 'allow' AND timestamp < '" + stop_date + "' AND timestamp > '" + start_date + "'"

	cur.execute(deny_q)
	deny_rows = cur.fetchall()
	cur.execute(allow_q)
	allow_rows = cur.fetchall()

	top_sites_allow_list = [] 
	top_sites_deny_list = []
	top_domains_allow_list = []
	top_domains_deny_list = []	

	for row in allow_rows:
		top_sites_allow_list.append(row[2])	
	 	split_domain = tldextract.extract(row[2])	
		final_domain = split_domain.domain + "." + split_domain.tld	
		top_domains_allow_list.append(final_domain)

	for row in deny_rows:
		top_sites_deny_list.append(row[2])
                split_domain = tldextract.extract(row[2])        
                final_domain = split_domain.domain + "." + split_domain.tld
		top_domains_deny_list.append(final_domain)

	
	top_100_sites_allow = Counter(top_sites_allow_list).most_common(100)
	top_100_sites_deny = Counter(top_sites_deny_list).most_common(100)
	top_1000_domains_allow = Counter(top_domains_allow_list).most_common(1000)
	top_1000_domains_deny = Counter(top_domains_deny_list).most_common(1000)
	allow_host_list_dedup = set(top_sites_allow_list)
	deny_host_list_dedup = set(top_sites_deny_list)
	allow_domain_list_dedup = set(top_domains_allow_list)
	deny_domain_list_dedup = set(top_domains_deny_list)

	total_queries = len(top_sites_allow_list) + len(top_sites_deny_list)
	total_allow_queries = len(top_sites_allow_list)
	total_deny_queries = len(top_sites_deny_list)

	total_queries_nice = str(locale.format("%d", total_queries, grouping=True))
	total_allow_queries_nice = str(locale.format("%d", total_allow_queries, grouping=True))
	total_deny_queries_nice = str(locale.format("%d", total_deny_queries, grouping=True))

	total_allow_list_dedup = set(top_sites_allow_list + top_domains_allow_list)
	detected_threat_list = email_report.check_threats(total_allow_list_dedup, threat_file_list)

	active_threat_files =  email_report.create_threat_log_files(detected_threat_list)

	now = datetime.datetime.now()
	date_time = now.strftime("%Y-%m-%d %H:%M") 
	subject = "AlohaDNS list optimization report for IP: %s on %s" % (client_ip, date_time)
	body_part_1 = "Thank you for using AlohaDNS.com, we appreciate the support and strive to make the internet a safer place.\n\nBelow is your nightly report on what domains and host have been allowed/visited and which have been blocked.\n\nReport for time period: %s to %s \nReport for IP Address: %s \nList Type: %s \nTotal Queries: %s \n\nCustom Filter:\nTotal Allowed Queries: %s \nTotal Denied Queries: %s \n" % (start_date, stop_date, client_ip, client_list_type, total_queries_nice, total_allow_queries_nice, total_deny_queries_nice) 

	printable_threat_list = []
	for item in active_threat_files:
		temp = item.split('/')
	 	temp = temp[-1] + " - see attached file\n"
		printable_threat_list.append(temp)
	printable_threats = ''.join(printable_threat_list)
	
	if (not printable_threats):
		printable_threats = "None"
	
	body_part_2 = "\n\n\nPotential Threats Accessed : \n%s" % (printable_threats)

	full_body = body_part_1 + body_part_2

	email_report.send_mail("AlohaDNS Optimizer <optimzer@alohadns.com>", [client_email], subject, full_body, active_threat_files)

	email_report.purge_temp_files(active_threat_files)
	
	email_report.email_report(top_100_sites_allow, top_100_sites_deny, top_1000_domains_allow, top_1000_domains_deny, client_ip, client_list_type, client_email, stop_date, start_date, total_queries, total_allow_queries, total_deny_queries)

print "LOOPSTART: GLOBAL"
today = datetime.date.today()
yesterday = datetime.timedelta(days=-1) + today
stop_date = str(today) + " 00:00:00"
start_date = str(yesterday) + " 00:00:00"

global_allow_q = "SELECT * FROM log WHERE disposition = 'allow' AND timestamp < '" + stop_date + "' AND timestamp > '" + start_date + "'"
global_deny_q = "SELECT * FROM log WHERE disposition = 'deny' AND timestamp < '" + stop_date + "' AND timestamp > '" + start_date + "'"

cur.execute(global_deny_q)
deny_rows = cur.fetchall()
cur.execute(global_allow_q)
allow_rows = cur.fetchall()

top_sites_allow_list = []
top_sites_deny_list = []
top_domains_allow_list = []
top_domains_deny_list = []

for row in allow_rows:
	top_sites_allow_list.append(row[2])
        split_domain = tldextract.extract(row[2])
        final_domain = split_domain.domain + "." + split_domain.tld
        top_domains_allow_list.append(final_domain)

for row in deny_rows:
        top_sites_deny_list.append(row[2])
        split_domain = tldextract.extract(row[2])
        final_domain = split_domain.domain + "." + split_domain.tld
        top_domains_deny_list.append(final_domain)


top_100_sites_allow = Counter(top_sites_allow_list).most_common(100)
top_100_sites_deny = Counter(top_sites_deny_list).most_common(100)
top_1000_domains_allow = Counter(top_domains_allow_list).most_common(1000)
top_1000_domains_deny = Counter(top_domains_deny_list).most_common(1000)
allow_host_list_dedup = set(top_sites_allow_list)
deny_host_list_dedup = set(top_sites_deny_list)
allow_domain_list_dedup = set(top_domains_allow_list)
deny_domain_list_dedup = set(top_domains_deny_list)

total_queries = len(top_sites_allow_list) + len(top_sites_deny_list)
total_allow_queries = len(top_sites_allow_list)
total_deny_queries = len(top_sites_deny_list)

total_allow_list_dedup = set(top_sites_allow_list + top_domains_allow_list)
detected_threat_list = email_report.check_threats(total_allow_list_dedup, threat_file_list)

email_report.create_threat_log_files(detected_threat_list)

email_report.email_report(top_100_sites_allow, top_100_sites_deny, top_1000_domains_allow, top_1000_domains_deny, "Global List", "Global Report", "anakaoka@trinet-hi.com", stop_date, start_date, total_queries, total_allow_queries, total_deny_queries)


if con:
        con.close()
