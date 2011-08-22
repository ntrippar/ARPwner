import urllib

class parameterObj(object):
    """
        object of analyze class
    """
    def __init__(self, type, request):
		self.type = type
		self.request = request

class analyzePost:
    """
        this class analyze the post data and check if in it there is any username or password
    """
    def __init__(self):
        self.User = 1
        self.Passwd = 2
        self.parameters = self.loadFile()
        
    def analyze(self,infologger,data,hostname):
        # debug print data   
        user, passwd = '',''  
        data = urllib.unquote_plus(data)
        data = data.split('&')
        for pdata in data:
            for parameter in self.parameters:
                if (pdata[:len(parameter.request)].lower() == parameter.request.lower() and len(pdata[:len(parameter.request)])>=1):
                    if parameter.type == self.User:
                        user = pdata[len(parameter.request):]
                    elif parameter.type == self.Passwd:
                        passwd = pdata[len(parameter.request):]
        if(len(user)>1 and len(passwd)>1):
            infologger.addInfo('HTTP', hostname, user, passwd)

    def loadFile(self):
        type = None
        data = []
        f = open('./Resources/request.lst','r')
        lines = f.readlines()
        for line in lines:
            line = line.strip()
            if line == '[user]':
                type = self.User
            elif line == '[pass]':
                type = self.Passwd
            else:
                if type == self.User:
                    data += [parameterObj(self.User,line)]
                elif type == self.Passwd:
                    data += [parameterObj(self.Passwd,line)]
        return data
