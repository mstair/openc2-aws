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
from openc2 import IPv4Address, IPv4Connection, SLPFTarget
import googleapiclient.discovery

logging.getLogger('googleapiclient.discovery').setLevel(logging.CRITICAL)

def connect(credfile):
    with open(credfile, 'r') as IN:
        creds = json.load(IN)
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = credfile
    return (creds['project_id'], googleapiclient.discovery.build('compute', 'v1', cache_discovery=False))

def addrule(project,client,name,direction,action,rule_number,vpc,ips,rules):
    firewall_data = dict(name=name,description="openc2 modified",
            direction=direction.upper(),priority=rule_number, network='global/networks/%s'%vpc)
    if direction == "ingress":
        firewall_data['sourceRanges']=ips 
    else:
        firewall_data['destinationRanges']=ips 
    if action == "allow":
        firewall_data['allowed']=rules
    else:
        firewall_data['denied']=rules

    try:
        request=client.firewalls().insert(project=project,body=firewall_data).execute()
    except googleapiclient.errors.HttpError as ex:
        print(ex)
        #todo:more error validation
        return None
    return request

def delrule(project,client,rulename):
    try:
        rule = client.firewalls().get(project=project,firewall=rulename).execute()
        request = client.firewalls().delete(project=project,firewall=rulename).execute()
    except googleapiclient.errors.HttpError as ex:
        #todo:more error validation
        return None
    #delete doesnt appear to return a response for valid request
    return 'foo'

def request(credsfile,slpf,requestid):
    def getvpcs(client,project):
        vpcs=[]
        request=client.networks().list(project=project).execute()
        for vpc in request['items']:
            vpcs.append(vpc['name'])
        return vpcs

    if slpf.target.type in ["ipv6_connection", "ipv6_net"]:
        return openc2.Response(status=501)

    ips = []
    ports = []
    direction = "ingress"
    protocol = "tcp"
    rule_number = "1000"
    rules = [ {"IPProtocol": "tcp"},
              {"IPProtocol": "udp"},
              {"IPProtocol": "icmp"} ]
    vpc = "default"
    response_requested = True

    project,client=connect(credsfile)

    ##actuator##
    vpcs = []
    if 'actuator' in slpf:
        if 'named_group' in slpf.actuator:
            if slpf.actuator.named_group in ["cloud","gcp"]:
                vpcs = getvpcs(client,project)
        elif 'asset_tuple' in slpf.actuator:
            try:
                project,vpc = slpf.actuator.asset_tuple
            except ValueError:
                #not our cloud
                return []
            #verify project matches
            try:
                vpc = client.networks().get(project=project,network=vpc).execute()
            except googleapiclient.errors.HttpError as ex:
                #todo:more error validation
                return []
            vpcs.append(vpc['name'])
        else:
            return openc2.Response(status=501,status_text="Unsupported actuator(%s)"%slpf.actuator)
    else:
        #no actuator, apply globally
        vpcs = getvpcs(client,project)

    ##targets##
    if slpf.target.type == "ipv4_net":
        ips.append(slpf.target.ipv4_net)
    elif slpf.target.type == "ipv4_connection":
        specifiers = slpf.target.keys()
        if 'protocol' in specifiers:
            protocol = slpf.target.protocol
        #ingress rule
        if 'src_addr' in specifiers:
            ips.append(slpf.target.src_addr)
        if 'dst_port' in specifiers:
            ports.append(slpf.target.dst_port)
        #egress rule
        if 'dst_addr' in specifiers:
            if len(ips):
                return openc2.Response(status=501,
                    status_text="Provide ingress or egress rule, not both")
            else:
                ips.append(slpf.target.dst_addr)
        if 'src_port' in specifiers:
            if len(ports):
                return openc2.Response(status=501,
                    status_text="Provide ingress or egress rule, not both")
            else:
                ports.append(slpf.target.src_port)
        rules = [ {"IPProtocol": protocol,
                    "ports": ports} ]
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
            pairs = dict(allow=["ipv4_net","ipv4_connection"],
                            deny=["ipv4_net","ipv4_connection"],
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
    _ips = []
    for ip in ips:
        if ip and not '/' in ip:
            ip = ip+"/32"
        _ips.append(ip)
    ips = _ips

    resps=[]
    if slpf.action in ["allow","deny"]:
        for vpc in vpcs:
            #encode vpc name into rule, as gcp doesnt allow dups across vpc networks
            rule_name = vpc+'-'+str(rule_number)
            rule = addrule(project,client,rule_name,direction,slpf.action,rule_number,vpc,ips,rules)
            resp = openc2.Response(status=500,status_text="Rule not updated")
            if rule:
                results = dict(slpf=dict(rule_number=rule_number,asset_tuple=[project,vpc]))
                resp = openc2.Response(status=200,results=results)
            if response_requested:
                resps.append(resp)
    elif slpf.action == "delete":
        for vpc in vpcs:
            rule_name = vpc+'-'+rule_number
            rule = delrule(project,client,rule_name)
            if rule and response_requested:
                results = dict(slpf=dict(rule_number=rule_number,asset_tuple=[project,vpc]))
                resps.append(openc2.Response(status=200,results=results))
    elif slpf.action == "query":
        resps.append(openc2.Response(status=200,results=results))
    else:
        resps.append(openc2.Response(status=501,status_text="Unsupported action (%s)"%slpf.action))
    return resps

if __name__ == "__main__":
    credsfile="gcp_credentials"
    requestid=str(uuid.uuid4())
    slpf=openc2.v10.slpf.SLPF(
            action="deny",
            target=IPv4Address(ipv4_net="1.2.3.4/32"),
            actuator=openc2.SLPFActuator(asset_tuple=["openc2-gcp","test"]),
            args=openc2.SLPFArgs(direction="ingress",insert_rule=5000)
    )
    for response in request(credsfile,slpf,requestid):
        x=openc2.parse(response)
        print(x)

        rule_number = response.results['slpf']['rule_number']

        slpf=openc2.v10.slpf.SLPF(
            action="delete",
            target=SLPFTarget(rule_number=rule_number),
            actuator=openc2.SLPFActuator(named_group="gcp"),
            args=openc2.SLPFArgs(direction="ingress")
        )
        for response in request(credsfile,slpf,requestid):
            x=openc2.parse(response)
            print(x)
