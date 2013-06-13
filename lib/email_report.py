import smtplib
import string
import locale
import os
from email.MIMEMultipart import MIMEMultipart
from email.MIMEBase import MIMEBase
from email.MIMEText import MIMEText
from email.Utils import COMMASPACE, formatdate
from email import Encoders


locale.setlocale(locale.LC_ALL, 'en_US')

def email_report( top_100_allow_list, top_100_deny_list, top_1000_domains_allow, top_1000_domains_deny, client_ip, client_list_type, client_email, stop_date, start_date, total_queries, total_allow_queries, total_deny_queries ):

  if not top_100_allow_list and not top_100_deny_list:
		return
	
	elif not top_100_deny_list:
		top_100_obj = []
		top_1000_domains_obj = []

                for i in range(len(top_100_allow_list)):
                        domain = top_100_allow_list[i][0]
                        count = top_100_allow_list[i][1]
                        new_list = domain + " : " + str(count) + "\n"
                        top_100_obj.append(new_list)
                top_100_string = string.join(top_100_obj, '')

		for i in range(len(top_1000_domains_allow)):
			domain = top_1000_domains_allow[i][0]
			count = top_1000_domains_allow[i][1]
			new_list = domain + " : " + str(count) + "\n"
			top_1000_domains_obj.append(new_list)
		top_1000_domains_string = string.join(top_1000_domains_obj, '')	

                SUBJECT = "Nightly DNS Totals Report for " + client_ip
                TO = client_email
                FROM = "AlohaDNS <logger@alohadns.com>"
                text = "Report for time period: " + start_date + " to " + stop_date + "\nReport for IP Address: " + client_ip + "\nList Type: " + client_list_type + "\nTotal Queries: " + str(locale.format("%d", total_queries, grouping=True))  + "\nTotal Allowed Queries: " + str(locale.format("%d", total_allow_queries, grouping=True)) + "\nTotal Denied Queries: " + str(locale.format("%d", total_deny_queries, grouping=True)) + "\n\nTop 1000 Accessed Domains (domain name : number of lookups)\n" + top_1000_domains_string + "\nTop 100 Accessed Hosts: (host name : number of lookups)\n" + top_100_string
                BODY = string.join((
                        "From: %s" % FROM,
                        "To: %s" % TO,
                        "Subject: %s" % SUBJECT ,
                        "",
                        text
                        ), "\r\n")
                server = smtplib.SMTP('localhost')
                server.sendmail(FROM, [TO], BODY)
                server.quit()
		return

		
	elif not top_100_allow_list:
		top_100_deny_obj = []
                top_1000_deny_domains_obj = []

		for i in range(len(top_100_deny_list)):
                        domain = top_100_deny_list[i][0]
                        count = top_100_deny_list[i][1]
                        new_list = domain + " : " + str(count) + "\n"
                        top_100_deny_obj.append(new_list)
                top_100_deny_string = string.join(top_100_deny_obj, '')

		for i in range(len(top_1000_domains_deny)):
                        domain = top_1000_domains_deny[i][0]
                        count = top_1000_domains_deny[i][1]
                        new_list = domain + " : " + str(count) + "\n"
                        top_1000_deny_domains_obj.append(new_list)
                top_1000_deny_domains_string = string.join(top_1000_deny_domains_obj, '')


                SUBJECT = "Nightly DNS Report for " + client_ip
                TO = client_email
                FROM = "AlohaDNS <logger@alohadns.com>"
		text = "Report for time period: " + start_date + " to " + stop_date + "\nReport for IP Address: " + client_ip + "\nList Type: " + client_list_type + "\nTotal Queries: " + str(locale.format("%d", total_queries, grouping=True))  + "\nTotal Allowed Queries: " + str(locale.format("%d", total_allow_queries, grouping=True)) + "\nTotal Denied Queries: " + str(locale.format("%d", total_deny_queries, grouping=True)) + "\n\nTop 1000 Blocked Domains: (domain name: number of lookups)\n" + top_1000_deny_domains_string  + "\n\nTop 100 Blocked Hosts: (host name : number of lookups)\n" + top_100_deny_string
                BODY = string.join((
                        "From: %s" % FROM,
                        "To: %s" % TO,
                        "Subject: %s" % SUBJECT ,
                        "",
                        text
                        ), "\r\n")
                server = smtplib.SMTP('localhost')
                server.sendmail(FROM, [TO], BODY)
                server.quit()
                return


	else:

		top_100_obj = []
		for i in range(len(top_100_allow_list)):
			domain = top_100_allow_list[i][0]
			count = top_100_allow_list[i][1]
			new_list = domain + " : " + str(count) + "\n"
			top_100_obj.append(new_list)
		top_100_string = string.join(top_100_obj, '')

		top_100_deny_obj = []
                for i in range(len(top_100_deny_list)):
                        domain = top_100_deny_list[i][0]
                        count = top_100_deny_list[i][1]
                        new_list = domain + " : " + str(count) + "\n"
                        top_100_deny_obj.append(new_list)
                top_100_deny_string = string.join(top_100_deny_obj, '')

		top_1000_deny_domains_obj = []
		for i in range(len(top_1000_domains_deny)):
                        domain = top_1000_domains_deny[i][0]
                        count = top_1000_domains_deny[i][1]
                        new_list = domain + " : " + str(count) + "\n"
                        top_1000_deny_domains_obj.append(new_list)
                top_1000_deny_domains_string = string.join(top_1000_deny_domains_obj, '')

		top_1000_domains_obj = []
	        for i in range(len(top_1000_domains_allow)):
                        domain = top_1000_domains_allow[i][0]
                        count = top_1000_domains_allow[i][1]
                        new_list = domain + " : " + str(count) + "\n"
                        top_1000_domains_obj.append(new_list)
                top_1000_domains_string = string.join(top_1000_domains_obj, '')

	

		SUBJECT = "Nightly DNS Report for " + client_ip
		TO = client_email
		FROM = "AlohaDNS <logger@alohadns.com>"
		text = "Report for time period: " + start_date + " to " + stop_date + "\nReport for IP Address: " + client_ip + "\nList Type: " + client_list_type + "\nTotal Queries: " + str(locale.format("%d", total_queries, grouping=True))  + "\nTotal Allowed Queries: " + str(locale.format("%d", total_allow_queries, grouping=True)) + "\nTotal Denied Queries: " + str(locale.format("%d", total_deny_queries, grouping=True)) + "\n\n Top 1000 Accessed Domains (domain name : number of lookups)\n" + top_1000_domains_string + "\n\nTop 100 Accessed Hosts: (host name : number of lookups)\n" + top_100_string + "\n\nTop 1000 Blocked Domains: (domain name : number of lookups)\n" + top_1000_deny_domains_string + "\n\nTop 100 Blocked Hosts: (host name : number of lookups)\n" + top_100_deny_string 
		BODY = string.join((
        		"From: %s" % FROM,
        		"To: %s" % TO,
        		"Subject: %s" % SUBJECT ,
        		"",
        		text
        		), "\r\n")
		server = smtplib.SMTP('localhost')
		server.sendmail(FROM, [TO], BODY)
		server.quit()	
		return

	return

def read_threat_files_list(threat_list_folder):
	threat_file_list = []
	for root, subFolders, files in os.walk(threat_list_folder):
		for file in files:
			f = os.path.join(root,file)
			threat_file_list.append(f)	
	return threat_file_list


def check_threats(query_list, threat_file_list):
	threat_dict = {}
	detected_threat_dict = {}
	for item in threat_file_list:
		threat_list = [line.strip() for line in open( item )]
		threat_list = set(threat_list)
		threat_dict.update({item:threat_list})
	for key, value in threat_dict.iteritems():
		threats = set(query_list) & set(value)
		detected_threat_dict.update({key:threats})
	return detected_threat_dict

def create_threat_log_files(detected_threat_dict):
	temp_threat_list = []
	for key, value in detected_threat_dict.iteritems():
		threat_list_name = os.path.basename(key)
		if not value:
			print "NO THREAT: %s" % threat_list_name
		else:
                        file = "/tmp/%s.txt" % threat_list_name
			f = open(file, "wb")
			for item in value:
				f.write("%s\n" % item)
			f.close()
			temp_threat_list.append(file)
	return temp_threat_list

def purge_temp_files(filelist):
	for f in filelist:
		os.remove(f)
	return

def send_mail(send_from, send_to, subject, text, files=[], server="localhost"):
    assert type(send_to)==list
    assert type(files)==list

    msg = MIMEMultipart()
    msg['From'] = send_from
    msg['To'] = COMMASPACE.join(send_to)
    msg['Date'] = formatdate(localtime=True)
    msg['Subject'] = subject

    msg.attach( MIMEText(text) )

    for f in files:
        part = MIMEBase('application', "octet-stream")
        part.set_payload( open(f,"rb").read() )
        Encoders.encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % os.path.basename(f))
        msg.attach(part)

    smtp = smtplib.SMTP(server)
    smtp.sendmail(send_from, send_to, msg.as_string())
    smtp.close()

