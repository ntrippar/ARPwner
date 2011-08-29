"""Telnet password logger"""
PROPERTY={}
PROPERTY['NAME']="Telnet Logger"
PROPERTY['DESC']="This logs all the Telnet accounts"
PROPERTY['AUTHOR']='localh0t'
PROPERTY['ENABLED']=True
PROPERTY['TYPE']='TCP'
PROPERTY['SPORT']=23
PROPERTY['DPORT']=23
user = None
passwd = None

class plugin():
    def __init__(self, traffic, logger):
        self.traffic = traffic
        self.logger = logger
    
    def analyze(self):
        global user, passwd
        data = self.traffic.data.data
        lines = data.split('\r\n')
        for line in lines:
            if(line[:4].lower() == "user"):
                user = line[5:]
            elif(line[:4].lower() == "pass"):
                passwd = line[5:]
        if (user != None and passwd != None):
                self.logger.addInfo('Telnet',self.traffic.dst,user,passwd)
                user = None
                passwd = None
