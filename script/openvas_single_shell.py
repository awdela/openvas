# -*- coding: utf-8-8 -*-
#!/usr/bin/python

from threading import Semaphore
from functools import partial

import pdb
import logging
import MySQLdb as mdb
from openvas_lib import VulnscanManager, VulnscanException
import datetime
import time,sys,socket,re
import traceback
import xml.dom.minidom
import struct,string
import uuid
import requests
import json
from IPy import IP
#db_name='bds'
#db_user = 'root'
#db_pass = 'smp123'
#db_ip = '192.168.3.220'

mask=0xFFFFFF00
ip_single = re.compile("^([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])$")

ip_segment = re.compile("^([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])\/([1-9]|[1-2][0-9]|3[0-2])$")

ip_field = re.compile("^([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])-([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])\."\
                +"([01]?\d\d?|2[0-4]\d|25[0-5])$")

xml_path = './csp-config.xml'


class IpOper(object):
    def __init__(self,ip_param):
        self.ip_list=[]
        self.ip_param = ip_param

    def getIpList(self):
        if(ip_single.search(self.ip_param)):
            self.ip_list.append(self.ip_param)

        elif(ip_segment.search(self.ip_param)):
            for ip in IP(self.ip_param):
                ipstr = str(ip)
                if ipstr[-2:len(ipstr)]=='.0' or ipstr[-3:len(ipstr)]=='255':
                    continue
                self.ip_list.append(ipstr)
                
        elif(ip_field.search(self.ip_param)):
            iparr = self.ip_param.split('-')
            ip_val1 = socket.ntohl(struct.unpack("I",socket.inet_aton(str(iparr[0])))[0])
            ip_val2 = socket.ntohl(struct.unpack("I",socket.inet_aton(str(iparr[1])))[0])
            if ip_val1&mask == ip_val2&mask :
                pos = iparr[0].rfind(".")
                ip_front = iparr[0][:(pos+1)]
                ip_from_last_number = string.atoi(iparr[0].replace(ip_front,''))
                ip_to_last_number = string.atoi(iparr[1].replace(ip_front,''))
                if ip_from_last_number == ip_to_last_number:
                    self.ip_list.append(iparr[0])
                elif ip_from_last_number > ip_to_last_number:
                    for i in range(ip_to_last_number,ip_from_last_number):
                        ip_tmp = ip_front+str(i)
                        self.ip_list.append(ip_tmp)
                        #print "sql for clear is ",sql_for_clear
                else:
                    for i in range(ip_from_last_number,ip_to_last_number):
                        ip_tmp = ip_front+str(i)
                        self.ip_list.append(ip_tmp)
                        #print "sql for clear is ",sql_for_clear
        else:
            return []
        return self.ip_list


def get_config(conf_path):
    #打开xml文档
    dom = xml.dom.minidom.parse(conf_path)

    #得到文档元素对象
    root = dom.documentElement
    itemlist = root.getElementsByTagName('openvas-config')
    item = itemlist[0]
    openvas_addr = item.getAttribute("addr")
    openvas_user = item.getAttribute("user")
    openvas_pass = item.getAttribute("password") 
    csp_url = item.getAttribute("csp_url") 
    
    openvas_config = {'addr':openvas_addr,
                'user':openvas_user,
                'pass':openvas_pass,
                'csp_url':csp_url
                }
    #return db_config,openvas_config
    return openvas_config

class host_sample(object):
    def __init__(self):
        pass

    def create_payload(self,body,openvas_config):
        payload=[]
        header_content={}
        loadbody={}
        header={}
        header['LogType']='csp_vulner'
        header['rTime']=str(int(time.mktime(datetime.datetime.now().timetuple())) * 1000)
        header['rHost']=openvas_conf['addr']
        loadbody['headers'] = header
        loadbody['body']=body
        payload.append(loadbody)
        return payload


def my_print_status(i):
    print str(i)


def scan_entity(ip,openvas_conf):
    
    Sem = Semaphore(0)
    # Configure
    print "ip is",ip
    #print "openvas addr is",openvas_conf['addr']
    #print "openvas pass is",openvas_conf['pass']
    
    manager = VulnscanManager(openvas_conf['addr'].encode("utf-8"),\
                             openvas_conf['user'].encode("utf-8"),\
                             openvas_conf['pass'].encode("utf-8"))
    # Launch
    scan_id,target_id = manager.launch_scan(ip,
				profile = "Full and fast",
				callback_end = partial(lambda x: x.release(), Sem),
				callback_progress = my_print_status)
    # Wait
    Sem.acquire()
    # Finished scan
    print "finished"
    #scan_id=""
    #pdb.set_trace()
    #if get all results set False or set True 
    res_list= manager.get_results(scan_id,True)
    
    svc_name=''

    # initial requests
    requests.packages.urllib3.disable_warnings()
    #host_vuln = host_sample()

    for res in res_list:
        if not res.description:
            desc = ''
        else:
            desc = res.description
        create_time = str(int(time.mktime(datetime.datetime.now().timetuple())) * 1000)
        resentity['VulnerID'] = str(uuid.uuid1())
        resentity['Name'] = res.name
        resentity['HostIP'] = res.host
        resentity['Severity'] = res.severity
        resentity["Family"]=res.nvt.family
        resentity["Port"]=res.port.number
        resentity["Protocol"]=res.port.proto
        resentity["SvcName"]=str(res.port.number) + res.port.proto
        resentity["QOD"]=res.qod
        resentity["CVE"]=res.nvt.raw_cves
        resentity["BID"]=res.nvt.raw_bids
        resentity["CvssBase"]=res.nvt.cvss_base_vector
        resentity["CERT"]=res.nvt.cert
        resentity["Impact"]=res.nvt.impact
        resentity["Desc"]=desc
        resentity["Solution"]=res.nvt.solution
        resentity["Refer"]=res.nvt.raw_xrefs
        resentity["source"]="0"
        resentity["Time"]=create_time
		print "size of result list is ============", resentity

def my_launch_scanner(ipparams,openvas_conf):
    
    openvas_conf= get_config(xml_path)
    ip_obj = IpOper(ipparams)
    iplist = ip_obj.getIpList()
    for ip in iplist:
        print "scanning ip:",ip
        scan_entity(ip,openvas_conf)
    

def print_help():
    print """    Parameter format is not correct:
    parameters:
        support: 192.168.3.11 or 192.168.3.0/24 or 192.168.3.11-192.168.3.15
    example:
        python openvas_single_shell.py 192.168.3.11 
        or
        python openvas_single_shell.py 192.168.3.0/24 
        or 
        python openvas_single_shell.py 192.168.3.11-192.168.3.15
    """

   
if __name__ == "__main__":

    if len(sys.argv) < 2:
        print_help()
        sys.exit()

    user_param = sys.argv[1]
    print "user param is",user_param
    sql_for_clear = ""
    search_single = ip_single.search(user_param)
    search_segment = ip_segment.search(user_param)
    search_field = ip_field.search(user_param)
    if not (search_single or search_segment or search_field):
        print_help()
        sys.exit()

    openvas_conf = get_config(xml_path)
    my_launch_scanner(user_param,openvas_conf)

