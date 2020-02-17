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
import logging
import os
import openc2

from dxlclient.callbacks import EventCallback
from dxlclient.message import Event
from dxlbootstrap.util import MessageUtils

import importlib.util

# Configure local logger
logger = logging.getLogger(__name__)


class OpenC2CommandCallback(EventCallback):
    """
    'openc2cmdhandler' event handler registered with topic '/openc2/event/slpf/command'
    """

    def __init__(self, app):
        """
        Constructor parameters:

        :param app: The application this handler is associated with
        """
        super(OpenC2CommandCallback, self).__init__()
        self._app = app
    
        cloud=self._app._cloud
        file=os.path.join(os.path.dirname(os.path.abspath(__file__)),'%s.py'%cloud) 
        spec=importlib.util.spec_from_file_location(cloud,file)
        self._module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self._module)

        self._credsfile = os.path.abspath(os.path.join(app._config_dir,'%s_credentials'%cloud))

    def on_event(self, event):
        """
        Invoked when an event message is received.

        :param event: The event message
        """
        # Handle event
        logger.info("Event received on topic: '%s' with payload: '%s'",
                    event.destination_topic, MessageUtils.decode_payload(event))

        request_id=str(event.destination_topic).split('/')[-1]
        #verify uuid

        cmd = MessageUtils.decode_payload(event)
        slpf = openc2.parse(cmd)
        resps = self._module.request(self._credsfile,slpf,request_id)
        for resp in resps:
            evt = Event("/openc2/event/slpf/response/%s"%request_id)
            MessageUtils.encode_payload(evt, resp.serialize())
            self._app.client.send_event(evt)
