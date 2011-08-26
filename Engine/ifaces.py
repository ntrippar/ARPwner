from Engine.functions import ipfromHex, mactohex
import socket
import fcntl
import struct
import binascii

class ifacesObject(object):
   def __init__(self,name, ip, hwaddr, gateway, gwhwaddr):
        self.name = name
        self.ip = ip
        self.hwaddr = hwaddr
        self.gateway = gateway
        self.gwhwaddr = gwhwaddr

class getIfaces:
    def __init__(self):
        self.interfaces = self.getIfaces()

    def getMac(self,ifname):
        '''get mac address of iface, only works on unix'''
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
        return ''.join(['%02x' % ord(char) for char in info[18:24]])

    def getIp(self, ifname):  #get ip address of iface, only works on unix
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(),0x8915,struct.pack('256s', ifname[:15]))[20:24])

    def getarpData(self,iface, ip):
        data = file('/proc/net/arp').read().splitlines()[1:]
        for line in data:
            line = line.rsplit(' ')
            entry = filter(lambda x:len(x) >=1 and x ,line)
            if entry[5] == iface and entry[0] == ip:
                return entry[3]
        return None

    def getIfaces(self):
        '''get ifaces from /proc/net route and return an object array
           with the ip hwaddr of the iface and gateway'''
        route = []
        data = file('/proc/net/route').read().splitlines()[1:] 
        for line in data:
            line = line.replace('\t',' ').strip().rsplit(' ')
            if line[2] != '00000000':
                route +=[ifacesObject(line[0], self.getIp(line[0]), binascii.unhexlify(self.getMac(line[0])),
                         ipfromHex(line[2]),mactohex(self.getarpData(line[0],ipfromHex(line[2]))))]
        return route

