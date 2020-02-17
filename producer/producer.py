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
parser.add_argument('jsonfile',help='openc2 json command file')
args = parser.parse_args()

# Create the client
with DxlClient(config) as client:

    responses = 0
    class ResponseCallback(EventCallback):
        def on_event(self, event):
            global responses
            responses +=1
            print("Event received on topic: %s"%event.destination_topic)
            x=MessageUtils.decode_payload(event)
            y=json.loads(x)
            print(json.dumps(y, sort_keys=True,indent=4))

    # Connect to the fabric
    client.connect()
    logger.info("Connected to DXL fabric.")

    with open(args.jsonfile,'r') as IN:
        cmd = json.load(IN)

    slpf = SLPF(**cmd)

    client.add_event_callback("/openc2/event/slpf/response/#", ResponseCallback())

    request_id = uuid.uuid4()
    evt = Event("/openc2/event/slpf/command/%s"%str(request_id))

    print("Sending event to topic: %s"%evt.destination_topic)
    print(json.dumps(cmd, sort_keys=True,indent=4))

    MessageUtils.encode_payload(evt, slpf.serialize())
    client.send_event(evt)

    while True:
        #print("responses=%d"%responses)
        time.sleep(60)
