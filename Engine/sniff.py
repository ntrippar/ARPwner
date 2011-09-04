import sys
import threading

try:
    import Libs.dpkt as dpkt
except ImportError:
    sys.exit("[-] Couldn't import: ./Libs/dpkt")
try:
    import pcap
except ImportError:
    sys.exit("[-] Couldn't import: pypcap http://code.google.com/p/pypcap/")

class sniff(threading.Thread):
    def __init__(self, iface, logger, plugins, dns = None):
        threading.Thread.__init__(self)
        self.running = False
        self.protocols = plugins.plugins
        self.iface = iface
        self.logger = logger
        self.dnsSpoof = dns
        self.pc = pcap.pcap(self.iface.name)

    def run(self):
        for ts, pkt in self.pc:
            if(self.running == False): break
            try:
                packet = dpkt.ethernet.Ethernet(pkt)

                if packet.type == dpkt.ethernet.ETH_TYPE_IP:
                    packet = packet.data
                    if self.dnsSpoof != None and self.dnsSpoof.running == True:
                        if packet.p == 17:
                            udp = packet.data
                            if udp.dport == 53:
                                self.dnsSpoof.analyze(packet)

                    #plugin check and call
                    try:
                        for protocol in self.protocols:
                            if protocol.PROPERTY['ENABLED'] == True:
                                try:
                                    if (packet.data.dport == protocol.PROPERTY['DPORT'] or packet.data.sport==protocol.PROPERTY['SPORT']):
                                        protocol.plugin(packet,self.logger).analyze()
                                except(KeyError):
                                    pass
                    except(AttributeError):
                        pass
                except:
                    pass

