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
import boto3, botocore

def connect(credfile,profile="default"):
    os.environ["AWS_SHARED_CREDENTIALS_FILE"] = credfile
    session = boto3.Session(profile_name=profile)
    return session

def addrule(client,nacl,direction,action,ip,isv6,port,protocol,rule_number):
    egress=True
    if direction == "ingress":
        egress=False

    args=dict(NetworkAclId=nacl,Egress=egress,Protocol=protocol,RuleAction=action,RuleNumber=rule_number)
    if protocol == "1":
        #handle 58/ipv6
        type,code=port
        args['IcmpTypeCode']={'Code':code,'Type':type}
    if isv6:
        args['Ipv6CidrBlock']=ip
    else:
        args['CidrBlock']=ip
    if port:
        args['PortRange']={'From':port,'To':port}
    try:
        rc=client.create_network_acl_entry(**args)
    except botocore.exceptions.ClientError as ex:
        print(ex)
        rc=None
    if rc and rc['ResponseMetadata']['HTTPStatusCode']:
        print(rc)
        return (rc['ResponseMetadata']['HTTPStatusCode'],nacl,rule_number)
    return rc

def delrule(client,nacl,direction,rule_number):
    egress=True
    if direction == "ingress":
        egress=False
    try:
        rc = client.delete_network_acl_entry(NetworkAclId=nacl, RuleNumber=rule_number, Egress=egress)
    except botocore.exceptions.ClientError as ex:
        rc=None
    if rc and rc['ResponseMetadata']['HTTPStatusCode']:
        return (rc['ResponseMetadata']['HTTPStatusCode'],nacl,rule_number)
    return rc

def request(credsfile,slpf,requestid):
    def getnacls(session):
        nacls = {}
        for region in session.get_available_regions('ec2'):
            client = session.client('ec2',region_name=region)
            try:
                _nacls=client.describe_network_acls()
            except:
                continue
            if len(_nacls['NetworkAcls']):
                for x in _nacls['NetworkAcls']:
                    if not region in nacls:
                        nacls[region] = []
                    nacls[region].append(x['NetworkAclId'])
        return nacls

    ip = None
    port = None
    direction = "ingress"
    protocol = "-1"
    rule_number = 100
    response_requested = True

    #todo: dont need to connect for query
    session=connect(credsfile)

    ##actuator##
    nacls = {}
    if 'actuator' in slpf:
        if 'named_group' in slpf.actuator:
            if slpf.actuator.named_group in ["cloud","aws"]:
                nacls = getnacls(session)
        elif 'asset_tuple' in slpf.actuator:
            try:
                account,region,nacl = slpf.actuator.asset_tuple
            except ValueError:
                #not our cloud
                return []
            #todo:verify account matches
            filter = [ { 'Name': 'network-acl-id', 'Values': [ nacl ] } ]
            client = session.client('ec2',region_name=region)
            _nacl=client.describe_network_acls(Filters=filter)
            if not len(_nacl['NetworkAcls']):
                #not our account
                return []
            if not region in nacls:
                nacls[region] = []
            nacls[region].append(_nacl['NetworkAcls'][0]['NetworkAclId'])
        else:
            #not our cloud
            return []
    else:
        #no actuator, apply globally
        nacls = getnacls(session)

    ##targets##
    if slpf.target.type == "ipv4_net":
        ip=slpf.target.ipv4_net
    elif slpf.target.type == "ipv6_net":
        ip=slpf.target.ipv6_net
    elif slpf.target.type in ["ipv4_connection","ipv6_connection"]:
        specifiers = slpf.target.keys()
        if 'protocol' in specifiers:
            if slpf.target.protocol == 'tcp':
                protocol = "6"
            elif slpf.target.protocol == 'udp':
                protocol = "17"
            elif slpf.target.protocol == 'icmp':
                protocol = "1"
        #ingress rule
        if 'src_addr' in specifiers:
            ip = slpf.target.src_addr
        if 'dst_port' in specifiers:
            if protocol == 1:
                icmpcode=slpf.target.dst_port 
            else:
                port = slpf.target.dst_port
        #egress rule
        if 'dst_addr' in specifiers:
            if ip:
                return openc2.Response(status=501,
                    status_text="Provide ingress or egress rule, not both")
            else:
                ip = slpf.target.dst_addr
        if 'src_port' in specifiers:
            if port:
                return openc2.Response(status=501,
                    status_text="Provide ingress or egress rule, not both")
            else:
                if protocol == 1:
                    icmptype = slpf.target.src_port
                else:
                    port = slpf.target.src_port
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

    #hack for single ips
    if ip and not '/' in ip:
        ip = ip+"/32"

    resps=[]
    if slpf.action in ["allow","deny"]:
        for region,_nacls in nacls.items():
            for nacl in _nacls:
                client = session.client('ec2',region_name=region)
                rule = addrule(client,nacl,direction,slpf.action,ip,slpf.target.type.startswith("ipv6"),
                    (icmptype,icmpcode) if protocol==1 else port, protocol,rule_number)
                resp = openc2.Response(status=500,status_text="Rule not updated")
                if rule:
                    code,nacl,_rule = rule
                    if code == 200:
                        results = dict(slpf=dict(rule_number=rule_number,asset_tuple=['123456789012',region,nacl]))
                        resp = openc2.Response(status=200,results=results)
                if response_requested:
                    resps.append(resp)
    elif slpf.action == "delete":
        for region,_nacls in nacls.items():
            for nacl in _nacls:
                client = session.client('ec2',region_name=region)
                rule = delrule(client,nacl,direction,int(rule_number))
                if rule and response_requested:
                    code,nacl,_rule = rule
                    if code == 200:
                        results = dict(slpf=dict(rule_number=rule_number,asset_tuple=['123456789012',region,nacl]))
                        resp = openc2.Response(status=200,results=results)
                        resps.append(resp)
    elif slpf.action == "query":
        resps.append(openc2.Response(status=200,results=results))
    else:
        resps.append(openc2.Response(status=501,status_text="Unsupported action (%s)"%slpf.action))
    return resps

if __name__ == "__main__":
    credsfile="aws_credentials"
    requestid=str(uuid.uuid4())
    cmd=openc2.v10.slpf.SLPF(
            action="deny",
            target=IPv4Address(ipv4_net="1.2.3.4/32"),
            actuator=openc2.SLPFActuator(asset_tuple=["123456789012","us-east-1","acl-1c414064"]),
            args=openc2.SLPFArgs(direction="egress",insert_rule=1000)
    )
    slpf = openc2.parse(cmd)
     
    for response in request(credsfile,slpf,requestid):
        x=openc2.parse(response)
        print(x)

        rule_number = response.results['slpf']['rule_number']
        slpf=openc2.v10.slpf.SLPF(
            action="delete",
            target=SLPFTarget(rule_number=rule_number),
            args=openc2.SLPFArgs(direction="egress"))
        for response in request(credsfile,slpf,requestid):
            x=openc2.parse(response)
            print(x)
