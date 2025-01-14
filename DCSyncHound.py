#!/usr/bin/env python3
import xlsxwriter
import argparse
import logging
from importlib import util
import json
from tqdm import tqdm
import re
from multiprocessing import Process, Manager

if util.find_spec('py2neo') is None:
    print('[-] py2neo library is not installed, please execute the following before: pip3 install --upgrade py2neo')
    exit()

from py2neo import Graph, Node, NodeMatcher, Relationship, RelationshipMatcher

def load_file(file):
    ls_f=open(file,"r",encoding="utf-8")
    ls=ls_f.read().splitlines()
    ls_f.close()
    return ls

def load_file_read_all(file):
    ls_f=open(file,"r",encoding="utf-8")
    ls=ls_f.read()
    ls_f.close()
    return ls

print("""
░█▀▄░█▀▀░█▀▀░█░█░█▀█░█▀▀░█░█░█▀█░█░█░█▀█░█▀▄
░█░█░█░░░▀▀█░░█░░█░█░█░░░█▀█░█░█░█░█░█░█░█░█
░▀▀░░▀▀▀░▀▀▀░░▀░░▀░▀░▀▀▀░▀░▀░▀▀▀░▀▀▀░▀░▀░▀▀░
                                by Mor David
""")

parser=argparse.ArgumentParser(description="DCSyncHound - This script analyzes the DCSync output file from several tools (such as Mimikatz, Secretsdump and SharpKatz...) and Hashcat's results and combine them into a single Excel file (xlsx)")
# Neo4j Settings
parser.add_argument('--dburi', dest='databaseUri', help='Database URI', default='bolt://localhost:7687')
parser.add_argument('-u','--dbuser', dest='databaseUser', help='Database user', default='neo4j')
parser.add_argument('-p','--dbpassword', dest='databasePassword', help='Database password', default='neo4j')
# Domain Information
parser.add_argument('-d','--domain', dest='domain', help='Domain Name (example: lab.local)',required=True)
# Files
parser.add_argument('-f','--file', dest='file_load', help='DCSync Output file',required=True)
parser.add_argument('-t','--type', dest='dcsync_type', help='Options: Mimikatz,Secretsdump,SharpKatz. Note: If you use mimikatz you need flags of /csv /all',required=True)
parser.add_argument('-c','--hashcat', dest='file_crack', help='Hashcat Output file',required=True)
# Output file
parser.add_argument('-o','--output', dest='output_file', help='Output file',required=True)
parser.add_argument('-b','--bloodhound', dest='bloodhound_enabled', help='Data Loading to Bloodhound Database', action='store_true')
parser.add_argument('-v','--verbose', dest='verbose', help='Verbose mode', action='store_true')
args=parser.parse_args()

# Set the logging level
loggingLevel=(logging.DEBUG if args.verbose else logging.INFO)

# Configure the root logger
logger=logging.getLogger('DCSyncHound')
logger.setLevel(loggingLevel)

# Configure the console logger
consoleLogger=logging.StreamHandler()
consoleLogger.setLevel(loggingLevel)
consoleFormatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
consoleLogger.setFormatter(consoleFormatter)
logger.addHandler(consoleLogger)

# Set the path for the log file
log_file_path='DCSyncHound_logs.log'

# Configure the file logger
fileLogger=logging.FileHandler(log_file_path)
fileLogger.setLevel(loggingLevel)
fileFormatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fileLogger.setFormatter(fileFormatter)
logger.addHandler(fileLogger)

# Add a log message
logger.debug('[*] Arguments: ' + str(args))

dcsync_type=args.dcsync_type.lower()

# Connect to neo4j
if args.bloodhound_enabled:
    try:
        graph=Graph(args.databaseUri, auth=(args.databaseUser, args.databasePassword))
        logger.info("[+] Connect to Neo4j server: "+args.databaseUri+" ("+args.databaseUser+")")
        matcher=NodeMatcher(graph)
    except Exception as e:
        logger.info("[+] Issue to connect your server: "+args.databaseUri)
        logger.info(str(e))
        exit()

# Parser of Hashcat Results
logger.info("[+] Parser Hashcat results")
dcsync_cracked=load_file(args.file_crack)
dcsync_cracked_final=list()
for cracked_row in dcsync_cracked:
    ntlm=cracked_row.split(":")[0].upper()
    plaintext=cracked_row.split(":")[1]
    dcsync_cracked_final.append(dict(ntlm=ntlm, plaintext=plaintext))

# Parser of secretsdump
logger.info("[+] Start parser the DCSync output file")
if dcsync_type == "secretsdump":
    dcsync_final=list()
    dcsync=load_file(args.file_load)
    for dcsync_row in dcsync:
        try:
            regex_me=r"^(.*?)\:(\d+)\:.*?\:(.*?)\:" # DCsync (Secretdump)
            if("(status=" in dcsync_row):
                regex_me=r"^(.*?)\:(\d+)\:.*?\:(.*?)\:.*?\(status\=(.*?)\)"
            dcsync_list=list(re.findall(regex_me, dcsync_row)[0])
            if ("\\" in dcsync_list[0]):
                domain=dcsync_list[0].split("\\")[0]
                user_id=dcsync_list[1]
                user=dcsync_list[0].split("\\")[1]
                ntlm=dcsync_list[2].upper()
            else:
                domain=args.domain.lower()
                user_id=dcsync_list[1]
                user=dcsync_list[0]
                ntlm=dcsync_list[2].upper()
            try:
                enabled=dcsync_list[3]
            except:
                enabled=""

            if(user == domain):
                domain=(args.domain).upper()

            adding_dict=dict(domain=domain, user_id=user_id, user=user, ntlm=ntlm, enabled=enabled)
            logger.debug(adding_dict)
            dcsync_final.append(adding_dict)
        except Exception as e:
            print(dcsync_row)
            print(str(e))
if dcsync_type == "mimikatz":
    regex_me=r"^\d+\s+(.*?)\s+(.*?)\s(\d+)$"
    dcsync_final=list()
    dcsync=load_file(args.file_load)
    for dcsync_row in dcsync:
        if "Exporting domain '" in dcsync_row:
            domain=dcsync_row.split("'")[1]
        dcsync_list=re.findall(regex_me, dcsync_row)
        if dcsync_list != []:
            dcsync_list_2=dcsync_list[0]
            user=dcsync_list_2[0]
            ntlm=dcsync_list_2[1].upper()
            points=dcsync_list_2[2]
            enabled="?"
            points_enabled=[512,66048,4096,532480]
            if int(points) in points_enabled:
                enabled="Enabled"
            else:
                enabled="Disabled"
            adding_dict=dict(domain=domain, user_id="", user=user, ntlm=ntlm, enabled=enabled)
            dcsync_final.append(adding_dict)
if dcsync_type == "sharpkatz":
    regex_me=r"^.*\s+(.*?)\s+([a-z0-9]{32})\s+(.*)$" # DCsync (SharpKatz)
    domain=(args.domain).upper()
    dcsync_final=list()
    dcsync=load_file(args.file_load)
    for dcsync_row in dcsync:
        dcsync_list=re.findall(regex_me, dcsync_row)
        if dcsync_list != []:
            dcsync_list_2=dcsync_list[0]
            user=dcsync_list_2[0]
            ntlm=dcsync_list_2[1].upper()
            if "ACCOUNTDISABLE" not in dcsync_list_2[2]:
                enabled="Enabled" 
            else:
                enabled="Disabled"
            adding_dict=dict(domain=domain, user_id="", user=user, ntlm=ntlm, enabled=enabled)
            logger.debug(adding_dict)
            dcsync_final.append(adding_dict)

# Matching
logger.info("[+] Creating full table in the memory")
final_result=list()
for row in tqdm(dcsync_final,desc="NTLM"):
    if args.bloodhound_enabled:
        query = "MATCH (u:User) WHERE last(split(u.objectid, '-')) CONTAINS $objectid AND u.name contains '@"+(row["domain"]).upper()+"' RETURN u LIMIT 1"
        node = graph.evaluate(query, objectid=row["user_id"])
        #node=matcher.match("User", name=row["user"].upper()+"@"+row["domain"].upper()).first()
        if node:
            node["ntlm"]=row["ntlm"]
            graph.push(node)
        else:
            query = "MATCH (u:User) WHERE last(split(u.objectid, '-')) CONTAINS $objectid AND u.name contains '@"+(args.domain).upper()+"' RETURN u LIMIT 1"
            node = graph.evaluate(query, objectid=row["user_id"])
            #node=matcher.match("User", name=row["user"].upper()+"@"+(args.domain).upper()).first()
            if node:
                node["ntlm"]=row["ntlm"]
                graph.push(node)
            else:
                logger.debug("Not found user named "+row["user"]+"@"+row["domain"]+", or "+row["user"]+"@"+(args.domain).upper())
    for row_cracked in dcsync_cracked_final:
            if(row_cracked["ntlm"] == row["ntlm"]):
                final_row=dict(Domain=row["domain"], User_ID=row["user_id"], User=row["user"], Plaintext=row_cracked["plaintext"], NTLM=row["ntlm"], Enabled=row["enabled"])
                final_result.append(final_row)
    

enabledUsersBool=(dcsync_type == "secretsdump" and "(status=" in load_file(args.file_load)[0]) or (dcsync_type == "sharpkatz" and "ACCOUNTDISABLE" in load_file_read_all(args.file_load))

if(enabledUsersBool):
    # Create a counter table
    final_password_table=list()
    password_counts={}
    # Count the occurrences of each password
    for user in final_result:
        if "Enabled" in user["Enabled"]:
            password=user['Plaintext']
            if password in password_counts:
                password_counts[password] += 1
            else:
                password_counts[password]=1
    # Password counts
    for password, count in password_counts.items():
        final_password_table.append(dict(Password=password,Counter=count))
else: # Show All All (Enabled and Disabled)
    # Create a counter table
    final_password_table=list()
    password_counts={}
    # Count the occurrences of each password
    for user in final_result:
        password=user['Plaintext']
        if password in password_counts:
            password_counts[password] += 1
        else:
            password_counts[password]=1
    # Password counts
    for password, count in password_counts.items():
        final_password_table.append(dict(Password=password,Counter=count))

# Create an Excel workbook for tables
if (args.output_file):
    logger.info("[+] Creating an Excel file...")
    workbook=xlsxwriter.Workbook(args.output_file+'.xlsx')
    worksheet=workbook.add_worksheet(name="Full DCSync Table")
    data_sorted=sorted(final_result, key=lambda x: x['Plaintext'])

    # Define a bold format
    bold_format=workbook.add_format({'bold': True})
    
    # Headers
    worksheet.freeze_panes(1, 0) # Freeze the header row
    headers=['Domain','User_ID','User','Plaintext','NTLM','Enabled']
    for col, header in enumerate(headers):
        worksheet.write(0, col, header, bold_format)
    # Add autofilter to the header row
    worksheet.autofilter(0, 0, 0, len(headers) - 1)

    # Write Table
    for row, entry in enumerate(data_sorted, start=1):
        for col, key in enumerate(headers):
            worksheet.write(row, col, entry.get(key, ''))

    # Adjust column widths to fit content
    for col, header in enumerate(headers):
        try:
            max_len=max(len(str(header)), max(len(str(entry.get(header, ''))) for entry in data_sorted))
            worksheet.set_column(col, col, max_len)
        except:
            pass

    # Add a new worksheet
    if(enabledUsersBool):
        password_table_name="Counter Table (Enabled only)"
    else:
        password_table_name="Counter Table (All users)"
    password_occ_worksheet=workbook.add_worksheet(name=password_table_name)
    # Write data to the new worksheet (optional)
    password_data_sorted=sorted(final_password_table, key=lambda x: x['Counter'], reverse=True)

    # Define a bold format
    bold_format=workbook.add_format({'bold': True})
    
    # Headers
    password_occ_worksheet.freeze_panes(1, 0) # Freeze the header row
    headers=['Password','Counter']
    for col, header in enumerate(headers):
        password_occ_worksheet.write(0, col, header, bold_format)

    # Write Table
    for row, entry in enumerate(password_data_sorted, start=1):
        for col, key in enumerate(headers):
            password_occ_worksheet.write(row, col, entry.get(key, ''))

    # Adjust column widths to fit content
    for col, header in enumerate(headers):
        try:
            max_len=max(len(str(header)), max(len(str(entry.get(header, ''))) for entry in password_data_sorted))
            password_occ_worksheet.set_column(col, col, max_len)
        except:
            pass

    workbook.close()
    logger.info("[+] Done to create Excel file ("+args.output_file+".xlsx)")
    #for user_object in tqdm(dcsync_cracked_final,desc="Updating NTLMs to Bloodhound"):
        #print(user_object)

# Update Bloodhound Plaintexts
if args.bloodhound_enabled:
    for user_object in tqdm(final_result,desc="Updating Plaintexts to Bloodhound"):
        try:
            query = "MATCH (u:User) WHERE last(split(u.objectid, '-')) CONTAINS $objectid AND u.name contains '@"+(user_object["Domain"]).upper()+"' RETURN u LIMIT 1"
            node = graph.evaluate(query, objectid=user_object["User_ID"])
            #node = matcher.match("User", name=user_object["User"].upper()+"@"+user_object["Domain"].upper()).first()
            if node:
                # Add parameters "Password" and "NTLM"
                node["password"] = user_object["Plaintext"]
                node["ntlm"] = user_object["NTLM"]
                node["owned"]=True # Legacy field
                
                # Handle system_tags for owned status
                if node["system_tags"] and "owned" in node["system_tags"]:
                    # Skip if already owned
                    pass
                elif not node["system_tags"]:
                    node["system_tags"] = "owned"
                else:
                    node["system_tags"] += " owned"
                
                # Commit the changes to the database
                graph.push(node)
            else:
                query = "MATCH (u:User) WHERE last(split(u.objectid, '-')) CONTAINS $objectid AND u.name contains '@"+(args.domain).upper()+"' RETURN u LIMIT 1"
                node = graph.evaluate(query, objectid=user_object["User_ID"])
                #node = matcher.match("User", name=user_object["User"].upper()+"@"+(args.domain).upper()).first()
                if node:
                    # Add parameters "Password" and "NTLM"
                    node["password"] = user_object["Plaintext"]
                    node["ntlm"] = user_object["NTLM"]
                    node["owned"]=True # Legacy field
                    
                    # Handle system_tags for owned status
                    if node["system_tags"] and "owned" in node["system_tags"]:
                        # Skip if already owned
                        pass
                    elif not node["system_tags"]:
                        node["system_tags"] = "owned"
                    else:
                        node["system_tags"] += " owned"

                    # Commit the changes to the database
                    graph.push(node)
                else:
                    logger.debug("Not found user named "+user_object["User"]+"@"+user_object["Domain"]+", or "+user_object["User"]+"@"+(args.domain).upper())
        except Exception as e:
            print("An error occurred:", e)
logger.info("[+] Done")
