import struct
import socket

def _inc_ipfield(addr, i):

    addr[i] = (addr[i] + 1) % 256
    if addr[i] == 0:
        if i > 0:
            addr = _inc_ipfield(addr, i-1)
        else:
            raise 'IP Overflow'
    return addr

def incIp(str_addr):
    addr = map(int,str_addr.split('.'))
    return '.'.join(map(str,_inc_ipfield(addr, len(addr)-1)))

def macFormat(addr):
    try:
        hwaddr = "%02x:%02x:%02x:%02x:%02x:%02x" % struct.unpack("BBBBBB",addr)
    except(struct.error):
        hwaddr = addr  
    return hwaddr

def ipFormat(addr):
    try:
        addr = socket.inet_ntoa(addr)
    except(socket.error):
        addr = addr
    return addr
