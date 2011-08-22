class infoObject(object):
    def __init__(self,service, host, user, passwd):
        self.service = service
        self.host = host
        self.user = user
        self.passwd = passwd
        

class logger():
    def __init__(self):
        self.information = []
        
    def addInfo(self,service,host,user,passwd):
        for obj in self.information:
            if (obj.service == service and obj.host == host and obj.user == user and obj.passwd == passwd):return
        self.information += [infoObject(service, host, user, passwd)]


#self.information += information += [{'Service':'FTP', 'Host':traffic.src,'User': user, 'Passwd': passwd}]
