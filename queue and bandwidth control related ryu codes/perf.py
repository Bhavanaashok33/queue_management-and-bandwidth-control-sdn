# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
import requests,json,unicodedata

#Simple Test scenario to validate Queue Configuration through controller,
#Configuration includes max rate, min rate etc.
#assingning flows to a particular Queue & validating the BW control

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.switches=set()
        self.dp1=True
        self.dp2=True
        self.dp3=True
        
    
    #Set up ovs switches & configure them to listen to the controller for queue configurations.
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
       
        self.switches.add(datapath)
        dpid = str(datapath.id)
        dpString = "000000000000000"+dpid#Fix this
        connection = "tcp:127.0.0.1:6632"
        print "Request Put",requests.put(url="http://localhost:8080/v1.0/conf/switches/"+dpString+"/ovsdb_addr",data=json.dumps(connection))
        print dpid,type(dpid)
    
        # install table-miss flow entry
        # We specify NO BUFFER to max_len of the output action due tot
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst, table_id=1)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst, table_id=1)
        datapath.send_msg(mod)
        
    #Extra feature, This feature handles the Queuecongig replies from switch.
    @set_ev_cls(ofp_event.EventOFPQueueGetConfigReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        print "datapath response for queue",(ev.msg.queues),ev.msg.datapath
        
        
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]
        
        
        '''
        Manual rules appoach without the use of QOS rules fron REST QOS APP
        if  dpid==1 and src=="00:00:00:00:00:01":
            actions.append(parser.OFPActionSetQueue(1))
        elif dpid==1 and src=="00:00:00:00:00:02":
            actions.append(parser.OFPActionSetQueue(0))
        elif dpid==2 and dst=="00:00:00:00:00:01":
            actions.append(parser.OFPActionSetQueue(1))
        elif dpid==2 and dst=="00:00:00:00:00:02":
            actions.append(parser.OFPActionSetQueue(0))'''
            
            
        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            
            # verify if we have a valid buffer_id, if yes avoid to send both
            # flow_mod & packet_out
            
            '''if(dpid==1 and self.dp1):
                self.dp1=False
                print("Defining Queues for ",dpid)
                data={"port_name": "s1-eth2", "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "500000"}, {"min_rate": "100000"}]}
                
                
                dat={"port_name": "s1-eth3", "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "200000"}, {"min_rate": "800000"}]}
                url="http://127.0.0.1:8080/qos/queue/0000000000000001"
                print "Request Post",requests.post(url="http://localhost:8080/qos/queue/0000000000000001",data=json.dumps(dat))
                req = parser.OFPQueueGetConfigRequest(datapath, 1);
                print "Sending Queue Req for ID",datapath.id
                datapath.send_msg(req)
                
                
                dat={"port_name": "s1-eth2", "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "200000"}, {"min_rate": "800000"}]}
                url="http://127.0.0.1:8080/qos/queue/0000000000000001"
                print "Request Post",requests.post(url="http://localhost:8080/qos/queue/0000000000000001",data=json.dumps(dat))
                req = parser.OFPQueueGetConfigRequest(datapath, 1);
                print "Sending Queue Req for ID",datapath.id
                datapath.send_msg(req)
                
                
                url="http://127.0.0.1:8080/qos/rules/0000000000000001"
                data={"match":{"nw_dst":"10.0.0.3","nw_src":"10.0.0.1"},"actions":{"queue":0},"priority":100}
                print "Request Post",requests.post(url=url,data=json.dumps(data))
                  
                  
                url="http://127.0.0.1:8080/qos/rules/0000000000000001"
                data={"match":{"nw_dst":"10.0.0.3","nw_src":"10.0.0.2",},"actions":{"queue":1},"priority":100}
                print "Request Post",requests.post(url=url,data=json.dumps(data))'''
            
            # Configuration for a linear topologu with 2 hosts at switch 1 & server at switch 3
            # Queues are configured for 2 ports on eth1 & eth2
            # Also flow rules are installed to enqueue packets to a particular queue if match is found.
            # More details in the test document.
            
			if(dpid==2 and self.dp2):
                self.dp2=False
                print("Defining Queues for ",dpid)
                data={"port_name": "s2-eth1", "type": "linux-htb", "max_rate": "1000000", "queues": [{"max_rate": "500000"}, {"max_rate": "400000"}]}
                url="http://localhost:8080/qos/queue/0000000000000002"
                print requests.post(url=url,data=json.dumps(data))
                
                '''req = parser.OFPQueueGetConfigRequest(datapath, 2);
                print "Sending Queue Req for ID",datapath.id
                datapath.send_msg(req)'''
    
                print("Defining Queues for ",dpid)
                data={"port_name": "s2-eth2", "type": "linux-htb", "max_rate": "1000000", "queues": [{"min_rate": "600000", "max_rate": "800000"}, {"min_rate": "300000", "max_rate": "500000"}]}
                url="http://localhost:8080/qos/queue/0000000000000002"
                print requests.post(url=url,data=json.dumps(data))
                
                '''req = parser.OFPQueueGetConfigRequest(datapath, 2);
                print "Sending Queue Req for ID",datapath.id
                datapath.send_msg(req)'''
                
                url="http://127.0.0.1:8080/qos/rules/0000000000000002"
                data={"match":{"nw_dst":"10.0.0.1","nw_src":"10.0.0.3"},"actions":{"queue":2},"priority":100}
                print "Request Post",requests.post(url=url,data=json.dumps(data))
                
                url="http://127.0.0.1:8080/qos/rules/0000000000000002"
                data={"match":{"nw_dst":"10.0.0.3","nw_src":"10.0.0.1"},"actions":{"queue":0},"priority":100}
                print "Request Post",requests.post(url=url,data=json.dumps(data))
                
                url="http://127.0.0.1:8080/qos/rules/0000000000000002"
                data={"match":{"nw_dst":"10.0.0.2","nw_src":"10.0.0.3"},"actions":{"queue":3},"priority":100}
                print "Request Post",requests.post(url=url,data=json.dumps(data))
                
                url="http://127.0.0.1:8080/qos/rules/0000000000000002"
                data={"match":{"nw_dst":"10.0.0.3","nw_src":"10.0.0.2"},"actions":{"queue":1},"priority":100}
                print "Request Post",requests.post(url=url,data=json.dumps(data))
             
                
                
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
