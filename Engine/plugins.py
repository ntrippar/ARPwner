import dircache

class Plugins:
    def __init__(self):
        self.plugins = []
        self.loadPlugins()

    def loadPlugins(self):
        filelist = dircache.listdir('./Protocols/')
        for filename in filelist:
            if not filename == "__init__.py" and filename[-3:]== '.py':
                tmp = __import__('Protocols.' + filename[:-3])
                self.plugins += [getattr(tmp, filename[:-3])]

    def enablePlugin(self,name):
        for plugin in self.plugins:
            if plugin.PROPERTY['NAME']==name:
                plugin.PROPERTY['ENABLED']=True

    def disablePlugin(self,name):
        for plugin in self.plugins:
            if plugin.PROPERTY['NAME']==name:
                plugin.PROPERTY['ENABLED']=False
