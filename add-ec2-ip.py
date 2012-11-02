#!/usr/bin/python
import sys
import urllib2
import boto
import argparse
from boto.ec2.connection import EC2Connection
from time import time
from datetime import datetime

''' WARN : Boto seems to require Python 2.x '''

'''
Public IP "providers" :
    http://checkip.amazonaws.com
    http://automation.whatismyip.com/n09230945.asp
'''

class WhatIsMyIpRetriever():
    def __str__( self ):
        return "http://checkip.amazonaws.com"

    def retrievePublicIp(self): 
        '''
        Includes setting the header to match the request
        see http://www.whatismyip.com/faq/automation.asp
        '''
        headers = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0' }
        return urllib2.urlopen(urllib2.Request("http://checkip.amazonaws.com/", None, headers )).read()

class AgentGatechIpRetriever():
    def __str__( self ):
        return "http://agentgatech.appspot.com/"
    def retrievePublicIp(self): 
        headers = { 'User-Agent' : 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:12.0) Gecko/20100101 Firefox/12.0' }
        return urllib2.urlopen(urllib2.Request("http://agentgatech.appspot.com/", None, headers)).read()

class DryRuleActivator():
    def __init__(self, securityGroup):
        pass
    def authorize(self, pub_ip_range, tcpPort):
        print "DRY RUN >> AUTH   >> ",  pub_ip_range, ", TCP: ", tcpPort
    def revoke(self, pub_ip_range, tcpPort):
        print "DRY RUN >> REVOKE  >> ",  pub_ip_range, ", TCP: ", tcpPort

class DefaultRuleActivator():
    def __init__(self, securityGroup):
        self.securityGroup=securityGroup

    def authorize(self, pub_ip_range, tcpPort):
        try:
            print "           AUTH-CHECK >> ",  pub_ip_range, ", TCP: ", tcpPort
            found = False
            for rule in self.securityGroup.rules:
                for cidr_ip in rule.grants:
                    if str(cidr_ip) == pub_ip_range and str(rule.from_port) == str(tcpPort) and str(rule.to_port) == str(tcpPort):
                        print "           AUTH-SKIP  >> ",  pub_ip_range, ", TCP: ", tcpPort
                        found = True
            if not found:
                print "           AUTH       >> ",  pub_ip_range, ", TCP: ", tcpPort
                res = self.securityGroup.authorize(ip_protocol='tcp', from_port=tcpPort, to_port=tcpPort, cidr_ip=pub_ip_range)
                print "           AUTH-RES   >> ",res
        except boto.exception.EC2ResponseError as e:
            print "EC2 error", e
            print "ERROR with ", pub_ip_range, tcpPort, "Press a key to ignore or CTRL+C"
            raw_input()
            
    def revoke(self, pub_ip_range, tcpPort):
        print "           REVOKE       >> ",  pub_ip_range, ", TCP: ", tcpPort
        res = self.securityGroup.revoke('tcp', tcpPort, tcpPort, cidr_ip=pub_ip_range)
        print "           REVOKE-RES   >> ",res

def lookupSecurityGroupByName(conn, name):
    try:
        rs = conn.get_all_security_groups(name)
        print "Security groups: ", len(rs), " found: ", rs
        return rs[0]
    except boto.exception.EC2ResponseError as e:
        print "EC2 error", e
        print "Error while looking for Security Group with name:", name
    rs = conn.get_all_security_groups()
    for sg in rs:
        print "   -> ", sg.name
    sys.exit(1)

#http://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
def createIpRange24(ip):
    return '%s0/24' % ip[:-len(ip.split('.')[-1])]

#http://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing
def createIpRange32(ip):
    return '%s/32' % ip

''' ~/.boto needed or read http://docs.pythonboto.org/en/latest/boto_config_tut.html '''
def addIPSecurity(region, groups, dryRun=False):
    conn = boto.ec2.connect_to_region(region)
    print "Connected to", conn
    ruleActivators  = {}
    for group in groups:
        ports = groups[group]
        print "Args :: Group : ", group, ", TCP ports: ", ports
        sg = lookupSecurityGroupByName(conn, group)
        print "Targeted Security Group: ", sg.name
        instances = sg.instances()
        print len(instances) ,"instances will be affected"
        publicIpRetriever = WhatIsMyIpRetriever()
        pub_ip = publicIpRetriever.retrievePublicIp().strip()
        print "Current public IP:", pub_ip, "(retrieved by ",publicIpRetriever,")"
        pub_ip_range = createIpRange32(pub_ip)
        print len(sg.rules), "rules actually defined in", sg.name
        for rule in sg.rules:
            print rule
        ruleActivators[group] = DryRuleActivator(sg) if dryRun else DefaultRuleActivator(sg)
        for port in ports:
            print "Setting", pub_ip_range, ":", port, "on", group
            ruleActivators[group].authorize(pub_ip_range, port)
        print "Now, ", len(sg.rules), "rules defined in", sg.name

    authTime=datetime.now()
    print "Started an authorized session at", authTime
    print "========================================================="
    print "=========== PRESS A KEY TO REVOKE RULES ================="
    print "========================================================="
    raw_input()
   
    print "Duration:",datetime.now()-authTime
    for group in groups:
        for port in groups[group]:
            print "Revoking", pub_ip_range, ":", port, "on", group
            ruleActivators[group].revoke(pub_ip_range, port)
        print "Now, ", len(sg.rules), "rules defined in", sg.name


if __name__=="__main__":
    parser = argparse.ArgumentParser(description='CLI control of AWS EC2 Security Groups', epilog="Example: add-ec2-ip.py mygroup1=22,443 mygroup2=8080")
    parser.add_argument('-d', '--dry', default=False, action="store_true")
    parser.add_argument('-r', '--region', default="us-east-1")
    parser.add_argument('ports', metavar='p', nargs='*', help='a securityGroup=port,port,port to open. You can add many of them')
    args = parser.parse_args()
    groups = dict([x.split('=') for x in args.ports])
    for group in groups:
        groups[group] = groups[group].split(',')
    addIPSecurity(args.region, groups, args.dry)
