import dircache
import sys

class Plugins:
    def __init__(self):
        self.plugins = []
        self.loadPlugins()

    def loadPlugins(self):
        filelist = dircache.listdir('./Protocols/')
        for filename in filelist:
            if not '.' in filename:
                sys.path.insert(0,'./Protocols/'+ filename)
                tmp = __import__(filename)
                self.plugins += [tmp]
                #debug print '<Loaded Module %s>'%(filename)
                sys.path.remove('./Protocols/'+ filename)

    def enablePlugin(self,name):
        for plugin in self.plugins:
            if plugin.PROPERTY['NAME']==name:
                plugin.PROPERTY['ENABLED']=True

    def disablePlugin(self,name):
        for plugin in self.plugins:
            if plugin.PROPERTY['NAME']==name:
                plugin.PROPERTY['ENABLED']=False
