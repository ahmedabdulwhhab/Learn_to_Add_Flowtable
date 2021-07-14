# Copyright (C) 2016 Li Cheng BUPT www.muzixing.com.
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
#
# Author:muzixing
# Time:2016/04/13
#

#ubuntu@ubuntu:~/sdn/ryu-controller/muzixing/ryu/ryu/app$ ryu-manager  ./multipath_Ah_Rev000_13.py ./ofctl_rest.py


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6
from ryu import utils


####new lines
from operator import attrgetter

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib import hub
import requests
import json
ryu_ip= '127.0.0.1'
ryu_port = '8080'
timer ='3000'
import os
switches = list()

############


class MULTIPATH_13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MULTIPATH_13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.FLAGS = True
        self.no_of_ticks=0          #new
        self.priority_incremntal=2  #new
        self.datapath_sw1=0
        self.parser_sw1={}
        self.datapath_sw2=0
        self.parser_sw2={}
        self.datapath_sw3=0
        self.parser_sw3={}
        self.datapath_sw4=0
        self.parser_sw4={}
        self.datapath_sw5=0
        self.parser_sw5={}
        self.monitor_thread = hub.spawn(self._monitor)      #new

    @set_ev_cls(
        ofp_event.EventOFPErrorMsg,
        [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.debug('OFPErrorMsg received: type=0x%02x code=0x%02x '
                          'message=%s', msg.type, msg.code,
                          utils.hex_array(msg.data))

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if not datapath.id in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        ### new
        if datapath.id==1:
            self.datapath_sw1=datapath
            self.parser_sw1 = datapath.ofproto_parser
            print("self.parser_sw1",self.parser_sw1)
        elif datapath.id==2:
            self.datapath_sw2=datapath
            self.parser_sw2 = datapath.ofproto_parser
            print("self.parser_sw2",self.parser_sw2)
        elif datapath.id==3:
            self.datapath_sw3=datapath
            self.parser_sw3 = datapath.ofproto_parser
            print("self.parser_sw3",self.parser_sw3)
        elif datapath.id==4:
            self.datapath_sw4=datapath
            self.parser_sw4 = datapath.ofproto_parser
            print("self.parser_sw4",self.parser_sw4)
        elif datapath.id==5:
            self.datapath_sw5=datapath
            self.parser_sw5 = datapath.ofproto_parser  
            print("self.parser_sw5",self.parser_sw5)
        
        ################################

        # install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, 0, match, actions)
        self.logger.info("switch:%s connected", dpid)

    def add_flow(self, datapath, hard_timeout, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                hard_timeout=hard_timeout,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def _build_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        actions = []
        if dst_port:
            actions.append(datapath.ofproto_parser.OFPActionOutput(dst_port))

        msg_data = None
        if buffer_id == datapath.ofproto.OFP_NO_BUFFER:
            if data is None:
                return None
            msg_data = data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=buffer_id,
            data=msg_data, in_port=src_port, actions=actions)
        return out

    def send_packet_out(self, datapath, buffer_id, src_port, dst_port, data):
        out = self._build_packet_out(datapath, buffer_id,
                                     src_port, dst_port, data)
        if out:
            datapath.send_msg(out)

    def flood(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        out = self._build_packet_out(datapath, ofproto.OFP_NO_BUFFER,
                                     ofproto.OFPP_CONTROLLER,
                                     ofproto.OFPP_FLOOD, msg.data)
        datapath.send_msg(out)
        self.logger.debug("Flooding msg")

    def arp_forwarding(self, msg, src_ip, dst_ip, eth_pkt):
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        out_port = self.mac_to_port[datapath.id].get(eth_pkt.dst)
        if out_port is not None:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth_pkt.dst,
                                    eth_type=eth_pkt.ethertype)
            actions = [parser.OFPActionOutput(out_port)]
            self.add_flow(datapath, 0, 1, match, actions)
            self.send_packet_out(datapath, msg.buffer_id, in_port,
                                 out_port, msg.data)
            self.logger.debug("Reply ARP to knew host")
        else:
            self.flood(msg)

    def mac_learning(self, dpid, src_mac, in_port):
        self.mac_to_port.setdefault(dpid, {})
        if src_mac in self.mac_to_port[dpid]:
            if in_port != self.mac_to_port[dpid][src_mac]:
                return False
        else:
            self.mac_to_port[dpid][src_mac] = in_port
            return True

    def send_group_mod(self, datapath,):
        ofproto = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        port_1 = 3
        queue_1 = ofp_parser.OFPActionSetQueue(0)
        actions_1 = [queue_1, ofp_parser.OFPActionOutput(port_1)]

        port_2 = 2
        queue_2 = ofp_parser.OFPActionSetQueue(0)
        actions_2 = [queue_2, ofp_parser.OFPActionOutput(port_2)]

        weight_1 = 50
        weight_2 = 50

        watch_port = ofproto_v1_3.OFPP_ANY
        watch_group = ofproto_v1_3.OFPQ_ALL

        buckets = [
            ofp_parser.OFPBucket(weight_1, watch_port, watch_group, actions_1),
            ofp_parser.OFPBucket(weight_2, watch_port, watch_group, actions_2)]

        group_id = 50
        req = ofp_parser.OFPGroupMod(datapath, ofproto.OFPFC_ADD,
                                     ofproto.OFPGT_SELECT, group_id, buckets)

        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        ip_pkt_6 = pkt.get_protocol(ipv6.ipv6)
        if isinstance(ip_pkt_6, ipv6.ipv6):
            actions = []
            match = parser.OFPMatch(eth_type=ether.ETH_TYPE_IPV6)
            self.add_flow(datapath, 0, 1, match, actions)
            return

        if isinstance(arp_pkt, arp.arp):
            self.logger.debug("ARP processing")
            if self.mac_learning(dpid, eth.src, in_port) is False:
                self.logger.debug("ARP packet enter in different ports")
                return

            self.arp_forwarding(msg, arp_pkt.src_ip, arp_pkt.dst_ip, eth)

        if isinstance(ip_pkt, ipv4.ipv4):
            self.logger.debug("IPV4 processing")
            out_port = None
            if eth.dst in self.mac_to_port[dpid]:
                if dpid == 1 and in_port == 1:
                    if self.FLAGS is True:
                        self.send_group_mod(datapath)
                        self.logger.info("send_group_mod")
                        self.FLAGS = False

                    actions = [parser.OFPActionGroup(group_id=50)]
                    match = parser.OFPMatch(in_port=in_port,
                                            eth_type=eth.ethertype,
                                            ipv4_src=ip_pkt.src)
                    self.add_flow(datapath, 0, 3, match, actions)
                    # asign output at 2
                    self.send_packet_out(datapath, msg.buffer_id,
                                         in_port, 2, msg.data)
                else:
                    #Normal flows
                    out_port = self.mac_to_port[dpid][eth.dst]
                    actions = [parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst,
                                            eth_type=eth.ethertype)
                    self.add_flow(datapath, 0, 1, match, actions)
                    self.send_packet_out(datapath, msg.buffer_id, in_port,
                                         out_port, msg.data)
            else:
                if self.mac_learning(dpid, eth.src, in_port) is False:
                    self.logger.debug("IPV4 packet enter in different ports")
                    return
                else:
                    self.flood(msg)



#################### new lines
    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug('register datapath: %016x', datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug('unregister datapath: %016x', datapath.id)
                del self.datapaths[datapath.id]

    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        #req = parser.OFPFlowStatsRequest(datapath)
        #datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)
    """
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body

        self.logger.info('datapath         '
                         'in-port  eth-dst           '
                         'out-port packets  bytes')
        self.logger.info('---------------- '
                         '-------- ----------------- '
                         '-------- -------- --------')
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            self.logger.info('%016x %8x %17s %8x %8d %8d',
                             ev.msg.datapath.id,
                             stat.match['in_port'], stat.match['eth_dst'],
                             stat.instructions[0].actions[0].port,
                             stat.packet_count, stat.byte_count)
	
							 
    """
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        
        self.logger.info('datapath         port     '
                         'rx-pkts  rx-bytes rx-error '
                         'tx-pkts  tx-bytes tx-error')
        self.logger.info('---------------- -------- '
                         '-------- -------- -------- '
                         '-------- -------- --------')
         
        self.no_of_ticks=self.no_of_ticks+1
        for stat in sorted(body, key=attrgetter('port_no')):
            
            self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                             ev.msg.datapath.id, stat.port_no,
                             stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                             stat.tx_packets, stat.tx_bytes, stat.tx_errors)
            
            if ev.msg.datapath.id==5 and stat.port_no==1:
                self.logger.info("after no. of ticks is %8d \nDifference between rx and tx packets at s5 port 1 is %016d",self.no_of_ticks,stat.tx_packets-stat.rx_packets)
                if (stat.tx_packets-stat.rx_packets) >5:
                    self.priority_incremntal+=1
                    ##switch 1
                    #self.add_flow(datapath, 0, 1, match, actions)
                    actions = [self.parser_sw1.OFPActionOutput(3)]
                    match = self.parser_sw1.OFPMatch(in_port=1, eth_dst="00:00:00:00:00:02",eth_src="00:00:00:00:00:01")
                    self.add_flow(self.datapath_sw1, 0, self.priority_incremntal, match, actions)                    
                    actions = [self.parser_sw1.OFPActionOutput(1)]
                    match = self.parser_sw1.OFPMatch(in_port=3, eth_dst="00:00:00:00:00:01",eth_src="00:00:00:00:00:02")
                    self.add_flow(self.datapath_sw1, 0, self.priority_incremntal, match, actions)                    
                    #switch 3
                    actions = [self.parser_sw3.OFPActionOutput(1)]
                    match = self.parser_sw3.OFPMatch(in_port=2, eth_dst="00:00:00:00:00:02",eth_src="00:00:00:00:00:01")
                    self.add_flow(self.datapath_sw3, 0, self.priority_incremntal, match, actions) 
                    actions = [self.parser_sw3.OFPActionOutput(2)]
                    match = self.parser_sw3.OFPMatch(in_port=1, eth_dst="00:00:00:00:00:01",eth_src="00:00:00:00:00:02")
                    self.add_flow(self.datapath_sw3, 0, self.priority_incremntal, match, actions)       
                    ##switch 4
                    actions = [self.parser_sw4.OFPActionOutput(1)]
                    match = self.parser_sw4.OFPMatch(in_port=2, eth_dst="00:00:00:00:00:02",eth_src="00:00:00:00:00:01")
                    self.add_flow(self.datapath_sw4, 0, self.priority_incremntal, match, actions)                    
                    actions = [self.parser_sw4.OFPActionOutput(2)]
                    match = self.parser_sw4.OFPMatch(in_port=1, eth_dst="00:00:00:00:00:01",eth_src="00:00:00:00:00:02")
                    self.add_flow(self.datapath_sw4, 0, self.priority_incremntal, match, actions)                    
                    #switch 5
                    actions = [self.parser_sw5.OFPActionOutput(2)]
                    match = self.parser_sw5.OFPMatch(in_port=3, eth_dst="00:00:00:00:00:02",eth_src="00:00:00:00:00:01")
                    self.add_flow(self.datapath_sw5, 0, self.priority_incremntal, match, actions) 
                    actions = [self.parser_sw5.OFPActionOutput(3)]
                    match = self.parser_sw5.OFPMatch(in_port=2, eth_dst="00:00:00:00:00:01",eth_src="00:00:00:00:00:02")
                    self.add_flow(self.datapath_sw5, 0, self.priority_incremntal, match, actions)                     
                    print("there is error on port 3 of s5")
                    #self._execute_scenario_1(self)
            if ev.msg.datapath.id==5 and stat.port_no==3:
                self.logger.info("after no. of ticks is %8d \nDifference between rx and tx packets at s5 port 3 is %016d",self.no_of_ticks,stat.tx_packets-stat.rx_packets)
                if (stat.tx_packets-stat.rx_packets) >5:
                    self.priority_incremntal+=1
                    #switch 
                    ##switch 1
                    actions = [self.parser_sw1.OFPActionOutput(2)]
                    match = self.parser_sw1.OFPMatch(in_port=1, eth_dst="00:00:00:00:00:02",eth_src="00:00:00:00:00:01")
                    self.add_flow(self.datapath_sw1, 0, self.priority_incremntal, match, actions)                    
                    actions = [self.parser_sw1.OFPActionOutput(1)]
                    match = self.parser_sw1.OFPMatch(in_port=2, eth_dst="00:00:00:00:00:01",eth_src="00:00:00:00:00:02")
                    self.add_flow(self.datapath_sw1, 0, self.priority_incremntal, match, actions)                    
                    #switch 2
                    actions = [self.parser_sw2.OFPActionOutput(2)]
                    match = self.parser_sw2.OFPMatch(in_port=1, eth_dst="00:00:00:00:00:02",eth_src="00:00:00:00:00:01")
                    self.add_flow(self.datapath_sw2, 0, self.priority_incremntal, match, actions) 
                    actions = [self.parser_sw2.OFPActionOutput(1)]
                    match = self.parser_sw2.OFPMatch(in_port=2, eth_dst="00:00:00:00:00:01",eth_src="00:00:00:00:00:02")
                    self.add_flow(self.datapath_sw2, 0, self.priority_incremntal, match, actions)                          
                    #switch 5
                    actions = [self.parser_sw5.OFPActionOutput(2)]
                    match = self.parser_sw5.OFPMatch(in_port=1, eth_dst="00:00:00:00:00:02",eth_src="00:00:00:00:00:01")
                    self.add_flow(self.datapath_sw5, 0, self.priority_incremntal, match, actions) 
                    actions = [self.parser_sw5.OFPActionOutput(1)]
                    match = self.parser_sw5.OFPMatch(in_port=2, eth_dst="00:00:00:00:00:01",eth_src="00:00:00:00:00:02")
                    self.add_flow(self.datapath_sw5, 0, self.priority_incremntal, match, actions)                                         
		    #self._execute_scenario_2(self)
                    print("there is error on port 1 of s5")

                


                
            
                
            
 
 
