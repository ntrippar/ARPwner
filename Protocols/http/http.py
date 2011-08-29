import Libs.dpkt as dpkt
from Engine import analyzepost

"""HTTP password logger"""
PROPERTY={}
PROPERTY['NAME']="HTTP Account Logger"
PROPERTY['DESC']="This logs all the HTTP accounts"
PROPERTY['AUTHOR']="ntrippar"
PROPERTY['ENABLED']=True
PROPERTY['TYPE']='TCP'
PROPERTY['SPORT']=00
PROPERTY['DPORT']=80

analyzeData = analyzepost.analyzePost()

class plugin():
    def __init__(self, traffic, logger):
        self.traffic = traffic
        self.logger = logger
    
    def analyze(self):
        data = self.traffic.data.data
        if self.traffic.data.dport == 80 and len(data) > 0:
            try:
                http = dpkt.http.Request(data)
                if len(http.body)>0:
                    analyzeData.analyze(self.logger, http.body, http.headers['host'])

            except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
                pass
    
