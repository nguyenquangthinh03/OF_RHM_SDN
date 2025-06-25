import json
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller import event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import icmp
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib import hub
import random
import time
from ryu.lib.packet import ether_types, udp, tcp
from ryu.lib import hub
from eventlet.event import Event
from collections import defaultdict
from dnslib import DNSRecord, QTYPE, RR, A


# Custom Event for time out
class EventMessage(event.EventBase):
    '''Create a custom event with a provided message'''
    def __init__(self, message, ip=None):
        super(EventMessage, self).__init__()
        self.msg = message
        self.ip = ip 

# Main Application
# Main Application
class MovingTargetDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _EVENTS = [EventMessage] 
    R2V_Mappings = {"10.0.0.1": "10.0.0.1",
                    "10.0.0.2": "10.0.0.2",
                    "10.0.0.3": "10.0.0.3",
                    "10.0.0.4": "10.0.0.4",
                    "10.0.0.5": "10.0.0.5", 
                    "10.0.0.6": "10.0.0.6", 
                    "10.0.0.7": "10.0.0.7", 
                    "10.0.0.8": "10.0.0.8" }
    V2R_Mappings = {}
    Resources = ["10.0.0.{}".format(i) for i in range(9, 29)]
    IP_TIMEOUTS = {
        "10.0.0.1": 9,
        "10.0.0.2": 9,
        "10.0.0.3": 9,
        "10.0.0.4": 9, 
        "10.0.0.5": 9,
        "10.0.0.6": 9,
        "10.0.0.7": 9,
        "10.0.0.8": 9,
    }
    #Pior = {1:20, 2:30, 3:40, 4:50, 5:60, 6:70, 7:80, 8:90,9:float('inf')}   
    Pior = {1:20, 2:20, 3:20, 4:20, 5:20, 6:20, 7:20, 8:20,9:float('inf')} 
    Used_Resources = set()
    DOMAIN2RIP = {  # tuỳ ý đổi tên miền
    "host1.mtd.": "10.0.0.1",
    "host2.mtd.": "10.0.0.2",
    "host3.mtd.": "10.0.0.3",
    "host4.mtd.": "10.0.0.4",
    "host5.mtd.": "10.0.0.5",
    "host6.mtd.": "10.0.0.6",
    "host7.mtd.": "10.0.0.7",
    "host8.mtd.": "10.0.0.8"
}
    CheckUpDate = {
        "10.0.0.1": False,
        "10.0.0.2": False,
        "10.0.0.3": False,
        "10.0.0.4": False, 
        "10.0.0.5": False,
        "10.0.0.6": False,
        "10.0.0.7": False,
        "10.0.0.8": False,
    }
    DNS_IP  = "10.0.0.30"
    DNS_MAC = "00:00:00:00:00:30" 
    def start(self):
        '''
            Append a new thread which calls the TimerEventGen function which generates timeout events
            every 30 seconds & sends these events to its listeners
            Reference: https://sourceforge.net/p/ryu/mailman/ryu-devel/?viewmonth=201601&viewday=12
        '''
        super(MovingTargetDefense, self).start()
    def __init__(self, *args, **kwargs):
        super(MovingTargetDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = set()
        self.HostAttachments = {}
        self.offset_of_mappings = 0
        self.timer_threads = {}  # Store timer threads for each IP
        self.active_sessions = {}  # Track active sessions: {(src_ip, dst_ip, proto): last_seen_time}
        self.session_timeout = 20  # Timeout for inactive sessions (seconds)
        self.ready = defaultdict(Event)   # mỗi IP có 1 Event
        self.SESSION_LOG = "session_log.txt"
        self.IP_MUTATION_LOG = "ip_mutation_log.txt"

    def TimerEventGen(self, ip):
        '''
        A function which generates timeout events for a specific IP based on its timeout period
        '''
        timeout = self.Pior[self.IP_TIMEOUTS[ip]]
        while True:
            timeout = self.Pior[self.IP_TIMEOUTS[ip]]
            if(timeout > 0 and self.CheckUpDate[ip] == False):
                self.send_event_to_observers(EventMessage("TIMEOUT", ip))
                hub.sleep(timeout)
            elif (timeout > 0 and self.CheckUpDate[ip] == True):
                self.CheckUpDate[ip] = False
                hub.sleep(timeout)
            else:
                break
    # def has_active_session(self, ip):
    #     '''
    #     Check if the IP is involved in any active session
    #     '''
    #     for (src, dst, proto), last_seen in list(self.active_sessions.items()):
    #         # Remove expired sessions
    #         if(proto == 'arp'):
    #            continue
    #         if src == ip or dst == ip:
    #             return True
    #     return False

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def handleSwitchFeatures(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths.add(datapath)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
    @set_ev_cls(EventMessage)
    def update_resources(self, ev):
        '''
        Update resources for a specific IP on timeout, only if no active sessions
        '''
        if ev.msg == "TIMEOUT" and ev.ip:
            ip = ev.ip
            last_octet = ip.split('.')[-1]
            host_name = f"host {last_octet}"
            # Check if IP is involved in active sessions
            current_time = time.time()
            timeleft = 0
            src_del = None
            dst_del = None
            proto_del = None
            def check_timeout():
                nonlocal timeleft, src_del, dst_del, proto_del, current_time
                current_time = time.time()
                timeleft = 0
                for (src, dst, proto), last_seen in list(self.active_sessions.items()):
                    # Remove expired sessions
                    if proto == 'arp':
                        continue
                    if current_time - last_seen > self.session_timeout:
                        del self.active_sessions[(src, dst, proto)]
                    elif src == ip or dst == ip:
                        if timeleft < self.session_timeout - (current_time - last_seen):
                            timeleft = self.session_timeout - (current_time - last_seen)
                            src_del = src
                            dst_del = dst
                            proto_del = proto
                if timeleft > 0:    
                    return True
                return False
            def perform_mutation():
                if check_timeout():
                    print(f"[{time.strftime('%M:%S')}] Delaying mutation for {host_name} due to active session")
                    hub.spawn_after(timeleft, perform_mutation)  # Lên lịch mutation sau timeleft giây
                    self.CheckUpDate[ip] = True
                    return
                available_resources = list(set(self.Resources) - self.Used_Resources)
                if available_resources:
                    old_vip = self.R2V_Mappings[ip] 
                    new_vIP = random.choice(available_resources)
                    if self.R2V_Mappings[ip] in self.Used_Resources:
                        self.Used_Resources.discard(self.R2V_Mappings[ip])
                    self.R2V_Mappings[ip] = new_vIP
                    self.Used_Resources.add(new_vIP)
                    self.V2R_Mappings = {v: k for k, v in self.R2V_Mappings.items()}
                    print(f"[{time.strftime('%M:%S')}] Mapping for {host_name}:", self.R2V_Mappings[ip])
                    timestamp = time.strftime("%M:%S", time.localtime())
                    with open(self.IP_MUTATION_LOG, "a") as f:
                        f.write(f"{timestamp} - {host_name} -> {new_vIP}\n")
                    self.ready[ip].send(True)  # Báo đã xong
                    self.ready[ip] = Event() 
                    for curSwitch in self.datapaths:
                        parser = curSwitch.ofproto_parser
                        match = parser.OFPMatch()
                        self.EmptyTable(curSwitch, ip_real=ip, ip_old_vip=old_vip)
                        ofp = curSwitch.ofproto
                        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                                        ofp.OFPCML_NO_BUFFER)]
                        self.add_flow(curSwitch, 0, match, actions)
            if check_timeout():
                print(f"[{time.strftime('%M:%S')}] Delaying mutation for {host_name} due to active session")
                if(src_del, dst_del, proto_del) in self.active_sessions:
                    del self.active_sessions[(src_del, dst_del, proto_del)]   
                hub.spawn_after(timeleft, perform_mutation)  # Lên lịch mutation sau timeleft giây
                self.CheckUpDate[ip] = True
            else:
                perform_mutation()  # Thực thi ngay nếu không cần chờ



    def EmptyTable(self, datapath, ip_real, ip_old_vip=None):
        """Delete flows whose src/dst match ip_real hoặc ip_old_vip."""
        ofp    = datapath.ofproto
        parser = datapath.ofproto_parser

        def _del_match(ip_addr):
            if not ip_addr:
                return
            for fld in ('ipv4_src',):
                match = parser.OFPMatch(eth_type=0x0800, **{fld: ip_addr})
                mod = parser.OFPFlowMod(datapath=datapath,
                                        command=ofp.OFPFC_DELETE,
                                        out_port=ofp.OFPP_ANY,
                                        out_group=ofp.OFPG_ANY,
                                        match=match)
                datapath.send_msg(mod)
            for fld in ('arp_spa',):
                match = parser.OFPMatch(eth_type=0x0806, **{fld: ip_addr})
                mod = parser.OFPFlowMod(datapath=datapath,
                                        command=ofp.OFPFC_DELETE,
                                        out_port=ofp.OFPP_ANY,
                                        out_group=ofp.OFPG_ANY,
                                        match=match)
                datapath.send_msg(mod)
        _del_match(ip_real)
        _del_match(ip_old_vip)

    def isRealIPAddress(self, ipAddr):
        return ipAddr in self.R2V_Mappings.keys()

    def isVirtualIPAddress(self, ipAddr):
        return ipAddr in self.R2V_Mappings.values()

    def isDirectContact(self, datapath, ipAddr):
        if ipAddr in self.HostAttachments.keys():
            return self.HostAttachments[ipAddr] == datapath
        return True

    def add_flow(self, datapath, priority, match, actions, buffer_id=None, hard_timeout=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            if hard_timeout is None:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                        priority=priority, match=match, instructions=inst,
                                        hard_timeout=hard_timeout)
        else:
            if hard_timeout is None:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst)
            else:
                mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                        match=match, instructions=inst, hard_timeout=hard_timeout)
        datapath.send_msg(mod)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def handlePacketInEvents(self, ev):
        actions = []
        pktDrop = False
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        arp_Obj = pkt.get_protocol(arp.arp)
        ip_Obj = pkt.get_protocol(ipv4.ipv4)
        tcp_Obj = pkt.get_protocol(tcp.tcp)
        udp_Obj = pkt.get_protocol(udp.udp)
        icmp_Obj = pkt.get_protocol(icmp.icmp)

        session_key = None
        proto = None
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        # ---------- ARP reply cho DNS_IP ----------
        arp_req = pkt.get_protocol(arp.arp)
        if arp_req and arp_req.opcode == 1 and arp_req.dst_ip == self.DNS_IP:
            eth_r = ethernet.ethernet(dst=eth.src, src=self.DNS_MAC, ethertype=0x0806)
            arp_r = arp.arp(opcode=2, src_mac=self.DNS_MAC, src_ip=self.DNS_IP,
                            dst_mac=eth.src,  dst_ip=arp_req.src_ip)
            pkt_out = packet.Packet()
            pkt_out.add_protocol(eth_r)
            pkt_out.add_protocol(arp_r)
            pkt_out.serialize()
            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                    buffer_id=ofproto.OFP_NO_BUFFER,
                                    in_port=ofproto.OFPP_CONTROLLER,
                                    actions=actions,
                                    data=pkt_out.data)
            datapath.send_msg(out)
            return  # rất quan trọng: dừng xử‑lý tiếp
        # ---------- HẾT ARP reply ----------
        if udp_Obj and udp_Obj.dst_port == 53:
            # raw DNS payload nằm ở cuối gói
            raw_dns = pkt.protocols[-1]    # kiểu bytes
            dns_req = DNSRecord.parse(raw_dns)
            qname = dns_req.q.qname
            name = str(qname).lower()         
            rip  = self.DOMAIN2RIP.get(name)
            if rip is None:
                return
            if self.IP_TIMEOUTS[rip] == 9 :
                self.IP_TIMEOUTS[rip] -=1
                if self.isRealIPAddress(rip):
                    self.timer_threads[rip] = hub.spawn(self.TimerEventGen, rip)
            if self.IP_TIMEOUTS[ip_Obj.src] == 9:
                self.IP_TIMEOUTS[ip_Obj.src] -=1
                if self.isRealIPAddress(ip_Obj.src):
                    self.timer_threads[ip_Obj.src] = hub.spawn(self.TimerEventGen, ip_Obj.src)
            # Giảm timeout của host vừa query, tối thiểu còn 1
            if ip_Obj.src in self.IP_TIMEOUTS :
                if  self.IP_TIMEOUTS[ip_Obj.src] > 1:
                    self.IP_TIMEOUTS[ip_Obj.src] -= 1
                if self.IP_TIMEOUTS[rip] > 1 :
                    self.IP_TIMEOUTS[rip] -=1
            # Tăng timeout các host khác, tối đa lên 10
            for ip_addr in list(self.IP_TIMEOUTS.keys()):
                if ip_addr != ip_Obj.src and ip_addr != rip and self.IP_TIMEOUTS[ip_addr] < 9:
                    self.IP_TIMEOUTS[ip_addr] += 1
            if self.isRealIPAddress(self.R2V_Mappings[rip]):
                try:
                    self.ready[rip].wait(timeout=1)
                except hub.Timeout:
                    pass  
            hub.spawn(self.reply_dns, datapath, in_port, eth, ip_Obj, udp_Obj, raw_dns)
            return
        if arp_Obj:
            src = arp_Obj.src_ip
            dst = arp_Obj.dst_ip
            proto = 'arp'

            # Convert virtual IPs to real IPs if necessary

            if self.isRealIPAddress(src) and src not in self.HostAttachments.keys():
                self.HostAttachments[src] = datapath.id

            if self.isRealIPAddress(src):
                match = parser.OFPMatch(eth_type=0x0806, in_port=in_port, arp_spa=src, arp_tpa=dst)
                spa = self.R2V_Mappings[src]
                actions.append(parser.OFPActionSetField(arp_spa=spa))

            if self.isVirtualIPAddress(dst):
                match = parser.OFPMatch(eth_type=0x0806, in_port=in_port, arp_tpa=dst, arp_spa=src)
                if self.isDirectContact(datapath=datapath.id, ipAddr=self.V2R_Mappings[dst]):
                    tpa = self.V2R_Mappings[dst]
                    actions.append(parser.OFPActionSetField(arp_tpa=tpa))
            elif self.isRealIPAddress(dst):
                match = parser.OFPMatch(eth_type=0x0806, in_port=in_port, arp_spa=src, arp_tpa=dst)
                if not self.isDirectContact(datapath=datapath.id, ipAddr=dst):
                    pktDrop = True
            else:
                pktDrop = True
            session_key = (src, dst, proto)
        elif ip_Obj and (tcp_Obj or udp_Obj or icmp_Obj):
            src = ip_Obj.src
            dst = ip_Obj.dst

            if self.isRealIPAddress(src) and src not in self.HostAttachments.keys():
                self.HostAttachments[src] = datapath.id

            if tcp_Obj:
                proto = 'tcp'
                proto_match = {'ip_proto': 6}  # TCP protocol number
              
            elif udp_Obj:
                proto = 'udp'
                proto_match = {'ip_proto': 17}  # UDP protocol number
              
            elif icmp_Obj:
                proto = 'icmp'
                proto_match = {'ip_proto': 1}  # ICMP protocol number
            

            if self.isRealIPAddress(src):
                match = parser.OFPMatch(eth_type=0x0800, in_port=in_port, ipv4_src=src, ipv4_dst=dst, **proto_match)
                ipSrc = self.R2V_Mappings[src]
                actions.append(parser.OFPActionSetField(ipv4_src=ipSrc))

            if self.isVirtualIPAddress(dst):
                match = parser.OFPMatch(eth_type=0x0800, in_port=in_port, ipv4_dst=dst, ipv4_src=src, **proto_match)
                if self.isDirectContact(datapath=datapath.id, ipAddr=self.V2R_Mappings[dst]):
                    ipDst = self.V2R_Mappings[dst]
                    actions.append(parser.OFPActionSetField(ipv4_dst=ipDst))
            elif self.isRealIPAddress(dst):
                match = parser.OFPMatch(eth_type=0x0800, in_port=in_port, ipv4_src=src, ipv4_dst=dst, **proto_match)
                if not self.isDirectContact(datapath=datapath.id, ipAddr=dst):
                    pktDrop = True
            else:
                pktDrop = True

            session_key = (src, dst, proto)
        dst_mac = eth.dst
        src_mac = eth.src
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src_mac] = in_port
        if dst_mac in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst_mac]
        else:
            out_port = ofproto.OFPP_FLOOD
        if pktDrop:
            # Nếu match chưa được khởi tạo, tạo match cơ bản theo src/dst
            if not 'match' in locals():
                match = parser.OFPMatch()
            self.add_flow(datapath, 1, match, [])  # actions=[] nghĩa là DROP
            return

        if not pktDrop:
            actions.append(parser.OFPActionOutput(out_port))
            if session_key: 
                # --- chỉ ghi khi đây là lần ĐẦU tiên thấy phiên này ---
                if session_key not in self.active_sessions :
                    timestamp = time.strftime("%M:%S", time.localtime())
                    if self.isVirtualIPAddress(src):
                        src_real = self.V2R_Mappings[src]     # tra bảng vIP → RIP
                    else:
                        src_real = src
                    host_src  = f"host{src_real.split('.')[-1]}"
                    log_line  = f"{timestamp} - {host_src}\n"
                    with open(self.SESSION_LOG, "a") as f:
                        f.write(log_line)
                self.active_sessions[session_key] = time.time()

        if out_port != ofproto.OFPP_FLOOD:
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

    def reply_dns(self, dp, in_port, eth, ip_pkt, udp_pkt, raw_dns_data):
        dns_req = DNSRecord.parse(raw_dns_data)
        qname = dns_req.q.qname
        name = str(qname).lower()         
        rip  = self.DOMAIN2RIP.get(name)
        vip = self.R2V_Mappings[rip]
        dns_resp = dns_req.reply()
        dns_resp.add_answer(
            RR(rname=qname, rtype=QTYPE.A, rclass=1, ttl=30, rdata=A(vip))
        )
        raw_reply = dns_resp.pack()

        eth_resp = ethernet.ethernet(dst=eth.src, src=eth.dst, ethertype=eth.ethertype)
        ip_resp  = ipv4.ipv4(src=ip_pkt.dst, dst=ip_pkt.src, proto=17, ttl=64)
        udp_resp = udp.udp(src_port=53, dst_port=udp_pkt.src_port, total_length=8+len(raw_reply))

        pkt_out = packet.Packet()
        for p in (eth_resp, ip_resp, udp_resp):
            pkt_out.add_protocol(p)
        pkt_out.add_protocol(raw_reply)     # thêm payload thuần bytes
        pkt_out.serialize()

        actions = [dp.ofproto_parser.OFPActionOutput(in_port)]
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=dp.ofproto.OFP_NO_BUFFER,
            in_port=dp.ofproto.OFPP_CONTROLLER, actions=actions,
            data=pkt_out.data)
        dp.send_msg(out)