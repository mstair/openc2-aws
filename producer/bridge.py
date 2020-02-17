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

from __future__ import absolute_import
from __future__ import print_function
import os
import sys
import argparse
import json
import time
import uuid
import pprint
import requests

from openc2.v10.slpf import SLPF

from dxlclient.client_config import DxlClientConfig
from dxlclient.client import DxlClient
from dxlclient.message import Message, Event, Request
from dxlclient.callbacks import EventCallback
from dxlbootstrap.util import MessageUtils

# Import common logging and configuration
sys.path.append(os.path.dirname(os.path.abspath(__file__)) + "../consumer/config/")
from common import *

# Configure local logger
logging.getLogger().setLevel(logging.ERROR)
logger = logging.getLogger(__name__)

# Create DXL configuration from file
config = DxlClientConfig.create_dxl_config_from_file(CONFIG_FILE)

parser = argparse.ArgumentParser(description='SLPF CLI Orchestrator')
parser.add_argument('--url',help='http url')
parser.add_argument('--cert',help='server cert',required=False)
parser.add_argument('--key',help='server key',required=False)
args = parser.parse_args()

# Create the client
with DxlClient(config) as client:

    responses = 0
    class ResponseCallback(EventCallback):
        def on_event(self, event):
            print("Event received on topic: %s"%event.destination_topic)
            request_id=str(event.destination_topic).split('/')[-1]

            cmd=json.loads(MessageUtils.decode_payload(event))
            try:
                slpf = SLPF(**cmd)
            except Exception as ex:
                print(ex)
                return

            print(slpf)
            headers = {'X-Request-ID': request_id,
                'Content-Type': 'application/openc2-cmd+json;version=1.0'}
            if(args.cert and args.key):
                r = requests.post(args.url, headers=headers, data = slpf.serialize(), cert=(args.cert, args.key), verify=False)
            else:
                r = requests.post(args.url, headers=headers, data = slpf.serialize(), verify=False)
            print(r.json())
            if r.status_code != 204:
                print(r.headers)
                if not 'Content-Type' in r.headers and \
                    not r.headers['Content-Type'] == 'application/openc2-rsp+json;version=1.0':
                    print("invalid response")
                response = Event("/openc2/event/slpf/response/%s"%request_id)
                MessageUtils.encode_payload(response, r.json())
                client.send_event(response)

    # Connect to the fabric
    client.connect()
    logger.info("Connected to DXL fabric.")

    client.add_event_callback("/openc2/event/slpf/command/#", ResponseCallback())
    
    while True:
        time.sleep(60)
