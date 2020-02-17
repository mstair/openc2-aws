'''
 BSD License
 Copyright 2020 AT&T Intellectual Property. All other rights reserved.
 Redistribution and use in source and binary forms, with or without modification, are permitted
 provided that the following conditions are met:
 1. Redistributions of source code must retain the above copyright notice, this list of conditions
    and the following disclaimer.
 2. Redistributions in binary form must reproduce the above copyright notice, this list of
    conditions and the following disclaimer in the documentation and/or other materials provided
    with the distribution.
 3. All advertising materials mentioning features or use of this software must display the
    following acknowledgement:  This product includes software developed by the AT&T.
 4. Neither the name of AT&T nor the names of its contributors may be used to endorse or
    promote products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY AT&T INTELLECTUAL PROPERTY ''AS IS'' AND ANY EXPRESS OR
 IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 SHALL AT&T INTELLECTUAL PROPERTY BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;  LOSS OF USE, DATA, OR PROFITS;
 OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 DAMAGE.
'''

import openc2, json, uuid, os, logging
from openc2 import IPv4Address, IPv4Connection, IPv6Address, IPv6Connection, SLPFTarget

from azure.common.client_factory import get_client_from_auth_file
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.network.models import NetworkSecurityGroup, SecurityRule, SecurityRuleAccess, SecurityRuleProtocol, SecurityRuleDirection
import msrestazure

def connect(credfile):
    os.environ["AZURE_AUTH_LOCATION"] = credfile
    client = get_client_from_auth_file(NetworkManagementClient)
    return client

def addrule(client,resource_group,nsg,name,direction,action,priority,sip,dip,sport,dport,protocol):
    access=SecurityRuleAccess.allow
    if action == "deny":
        access=SecurityRuleAccess.deny

    rule = SecurityRule(
            name=name,
            access=access,
            description='openc2 modified',
            destination_address_prefix=dip,
            destination_port_range=dport,
            direction=direction,
            priority=priority,
            protocol=protocol,
            source_address_prefix=sip,
            source_port_range=sport
    )
    try:
        rc = client.security_rules.create_or_update( 
            resource_group, nsg, name, rule) 
    except msrestazure.azure_exceptions.CloudError as ex:
        return None
    return rc.result() 

def delrule(client,resource_group,nsg,name):
    rc = client.security_rules.delete( 
        resource_group,
        nsg,
        name,
        polling=False,
        raw=True
    )
    return rc.result()

def request(credsfile,slpf,requestid):
    def getnsgs(client):
        nsgs = {}
        rc = client.network_security_groups.list_all()
        for nsg in rc:
            #parse resource group from id, should use corrent azure lib to list them
            resource_group = nsg.id.split('/')[4]
            if not resource_group in nsgs:
                nsgs[resource_group] = []
            nsgs[resource_group].append(nsg.name)
        return nsgs

    sip = '*'
    dip = '*'
    sport = '*'
    dport = '*'
    direction = SecurityRuleDirection.inbound
    protocol = SecurityRuleProtocol.asterisk
    rule_number = "1000"
    response_requested = True

    #TODO:dont need to auth/connect for query
    client=connect(credsfile)

    ##actuator##
    nsgs = {}
    if 'actuator' in slpf:
        if 'named_group' in slpf.actuator:
            if slpf.actuator.named_group in ["cloud","az"]:
                nsgs = getnsgs(client)
        elif 'asset_tuple' in slpf.actuator:
            try:
                subscription,resource_group,nsg = slpf.actuator.asset_tuple
            except ValueError:
                #not our cloud
                return []
            #verify subscription matches
            try:
                rc = client.network_security_groups.get(resource_group_name=resource_group,network_security_group_name=nsg)
            except msrestazure.azure_exceptions.CloudError:
                return []
            if not resource_group in nsgs:
                nsgs[resource_group] = []
            nsgs[resource_group].append(nsg)
        else:
            return openc2.Response(status=501,status_text="Unsupported actuator(%s)"%slpf.actuator)
    else:
        #no actuator, apply globally
        nsgs = getngs(client)

    ##targets##
    if slpf.target.type == "ipv4_net":
        sip=slpf.target.ipv4_net
    elif slpf.target.type == "ipv6_net":
        sip=slpf.target.ipv6_net
    elif slpf.target.type in ["ipv4_connection","ipv6_connection"]:
        specifiers = slpf.target.keys()
        if 'protocol' in specifiers:
            if slpf.target.protocol == 'tcp':
                protocol = SecurityRuleProtocol.tcp
            elif slpf.target.protocol == 'udp':
                protocol = SecurityRuleProtocol.udp
            elif slpf.target.protocol == 'icmp':
                protocol = SecurityRuleProtocol.icmp
        if 'src_addr' in specifiers:
            sip = slpf.target.src_addr
        if 'dst_port' in specifiers:
            dport = slpf.target.dst_port
        if 'dst_addr' in specifiers:
            dip = slpf.target.dst_addr
        if 'src_port' in specifiers:
            sport = slpf.target.src_port
    elif slpf.target.type == "slpf:rule_number":
        if not slpf.action == "delete":
            return openc2.Response(status=501,
                status_text="Invalid action/target pair")
        rule_number = slpf.target.rule_number
    elif slpf.target.type == "features":
        if not slpf.action == "query":
            return openc2.Response(status=501,
                status_text="Invalid action/target pair")       
        results = {}
        specifiers = list(slpf.target.values())[0]
        if 'versions' in specifiers:
            results['versions'] = ["1.0"]
        if 'profiles' in specifiers:
            results['profiles'] = ["slpf"]
        if 'pairs' in specifiers:
            pairs = dict(allow=["ipv4_net","ipv4_connection","ipv6_net","ipv6_connection"],
                            deny=["ipv4_net","ipv4_connection","ipv6_net","ipv6_connection"],
                            query=["features"],
                            delete=["slpf:rule_number"])
            results['pairs'] = pairs
    else:
        return openc2.Response(status=501,
            status_text="Unsupported target(%s)"%slpf.target)

    ##args##
    if 'args' in slpf:
        if 'response_requested' in slpf.args:
            if slpf.args.response_requested == "none":
                response_requested = False
        if 'slpf' in slpf.args:
            if 'direction' in slpf.args.slpf:
                direction = slpf.args.slpf.direction
            if 'insert_rule' in slpf.args.slpf:
                rule_number = slpf.args.slpf.insert_rule
                if rule_number > 4096:
                    return openc2.Response(status=501,
                        status_text="Invalid insert_rule, must be < 4096")

    resps=[]
    if slpf.action in ["allow","deny"]:
        for resource_group,_nsgs in nsgs.items():
            for nsg in _nsgs:
                asset_tuple=['12345678-90ab-cdef-1234-567890abcdef',resource_group,nsg]
                name = rule_number
                rule = addrule(client,resource_group,nsg,name,direction,slpf.action,rule_number,sip,dip,sport,dport,protocol)
                resp = openc2.Response(status=500,status_text="Rule not updated")
                if rule:
                    results = dict(slpf=dict(rule_number=name,asset_tuple=asset_tuple))
                    resp= openc2.Response(status=200,results=results)
                if response_requested:
                    resps.append(resp)
    elif slpf.action == "delete":
        for resource_group,_nsgs in nsgs.items():
            for nsg in _nsgs:
                asset_tuple=['12345678-90ab-cdef-1234-567890abcdef',resource_group,nsg]
                rule = delrule(client,resource_group,nsg,rule_number)
                if rule and response_requested:
                    if rule.response.status_code == 202:
                        results = dict(slpf=dict(rule_number=rule_number,asset_tuple=asset_tuple))
                        resp = openc2.Response(status=200,results=results)
                        resps.append(resp)
    elif slpf.action == "query":
        resps.append(openc2.Response(status=200,results=results))
    else:
        resps.append(openc2.Response(status=501,
            status_text="Unsupported action (%s)"%slpf.action))
    return resps

if __name__ == "__main__":
    credsfile="az_credentials"
    requestid=str(uuid.uuid4())
    slpf=openc2.v10.slpf.SLPF(
            action="deny",
            target=IPv4Address(ipv4_net="1.2.3.4/32"),
            actuator=openc2.SLPFActuator(asset_tuple=["12345678-90ab-cdef-1234-567890abcdef","test-rg","testvm-nsg"]),
            args=openc2.SLPFArgs(direction="ingress",insert_rule=900)
    )
    for response in request(credsfile,slpf,requestid):
        x=openc2.parse(response)
        print(x)

        rule_number = response.results['slpf']['rule_number']
        slpf=openc2.v10.slpf.SLPF(
            action="delete",
            target=SLPFTarget(rule_number=rule_number),
            actuator=openc2.SLPFActuator(named_group="cloud"),
            args=openc2.SLPFArgs(direction="ingress")
        )
        for response in request(credsfile,slpf,requestid):
            x=openc2.parse(response)
            print(x)
