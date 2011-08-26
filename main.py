import sys, os, time
from Engine import arp
from Engine import sniff
from Engine import httpstrip
from Engine.functions import macFormat, ipFormat
from Engine import plugins
from Engine import dnsSpoof
from Engine import ifaces
passwdList = None
gladefile="main.glade"

try:
 	import pygtk
  	pygtk.require("2.0")
except:
  	pass
try:
	import gtk
  	import gtk.glade
except:
	sys.exit(1)
gtk.gdk.threads_init()


class logger():
    def addInfo(self,service,host,user,passwd):
        passwdList.append([service, ipFormat(host), user, passwd])

class arpGui:
    def __init__(self):
        self.plugins = plugins.Plugins()
        self.load()
        self.logger = logger()
        self.dnsSpoof = dnsSpoof.dnsSpoof()
        self.iface = None
        self.arp = None
        self.sniff = False
        self.httpspwn = httpstrip.run_server(self.logger)

    def addlistColumn(self, Object, title, columnId):
        column = gtk.TreeViewColumn(title, gtk.CellRendererText(), text=columnId)
        column.set_resizable(True)		
        column.set_sort_column_id(columnId)
        Object.append_column(column)

    def scanNetwork(self,widget):
        if self.arp != None:
            self.networkList.clear()
            result,ip1,ip2 = scanDialog().run()
            if (result == gtk.RESPONSE_OK):
                lenght =  self.arp.scanRange(ip1,ip2)
                if (lenght >=1):
                    for target in self.arp.network:
                        self.networkList.append([target.ip])

    def startSniff(self,widget):
        if (self.iface != None):
            if (self.sniff.running == False):
                self.sniff.running = True
                self.lblSniffing.set_text('Pasive sniffing: ON')
                try:
                    self.sniff.start()
                except:
                    messageBox("couldn't start the Pasive sniffing")
            else:
                self.sniff.running = False
                self.lblSniffing.set_text('Pasive sniffing: OFF')
                self.sniff = sniff.sniff(self.iface, self.logger, self.plugins,self.dnsSpoof)

    def arpPoison(self,widget):
        if(self.arp != None):
            if (len(self.arp.targets)>0 and self.arp.running == False):
                self.arp.running = True
                self.lblArp.set_text('Arp: ON')
                self.arp.start()
            else:
                self.arp.running = False
                self.lblArp.set_text('Arp: OFF')
                self.arp = arp.ARP(self.iface)

    def exit(self,widget):
        try:
            self.arp.running = False
            self.sniff.running = False
            if self.httpspwn.running = True:
                self.httpspwn.stop()
            gtk.main_quit()
        except(AttributeError):
            gtk.main_quit()

    def httpStrip(self,widget):
        if (self.httpspwn.running == False):
            self.httpspwn.start()
            self.lblStrip.set_text('SSLstrip: ON')
        else:
            self.lblStrip.set_text('SSLstrip: OFF')
            self.httpspwn.stop()
            self.httpspwn = httpstrip.run_server(self.logger)


    def addTarget(self, treeview, iter, *args):
        model=treeview.get_model()
        iter = model.get_iter(iter)
        ip = model.get_value(iter, 0)
        self.arp.addipTarget(ip)
        self.targetsList.append([ip])
        self.networkList.remove(iter)

    def remTarget(self, treeview, iter, *args):
        model=treeview.get_model()
        iter = model.get_iter(iter)
        ip = model.get_value(iter, 0)
        self.arp.remipTarget(ip)
        self.networkList.append([ip])
        self.targetsList.remove(iter)


    def statusPlugin(self, treeview, iter, *args):
        model=treeview.get_model()

        iter = model.get_iter(iter)
        enabled = model.get_value(iter, 0)
        name = model.get_value(iter, 1)
        if enabled == True:
            self.plugins.disablePlugin(name)
            self.pluginsList.set_value(iter,0,False)
        else:
            self.plugins.enablePlugin(name)
            self.pluginsList.set_value(iter,0,True)
            

    def dnsRun(self,widget):
        if self.dnsSpoof.running == False:
            self.dnsSpoof.running = True
            self.lblDns.set_text('DNS spoofing: ON')
        else:
            self.dnsSpoof.running = False
            self.lblDns.set_text('DNS spoofing: OFF')

    def showAbout(self,widget):
        wTree=gtk.glade.XML(gladefile,"dialog")
        response = wTree.get_widget("dialog").run()
        if response == gtk.RESPONSE_DELETE_EVENT or response == gtk.RESPONSE_CANCEL:
            wTree.get_widget("dialog").hide()

    def load(self):
        global passwdList
        """
        In this function we are going to display the Main
        window and connect all the signals
        """
        self.wTree=gtk.glade.XML(gladefile,"Main")

        dic = {"on_Main_destroy" : self.exit
            , "on_cmdIface_activate" : self.setIface
            , "on_cmdScan_activate" : self.scanNetwork
            , "on_cmdSniff_activate" : self.startSniff
            , "on_cmdArp_activate" : self.arpPoison
            , "on_cmdStrip_activate": self.httpStrip
            , "on_lstNetwork_row_activated": self.addTarget
            , "on_lstTargets_row_activated": self.remTarget
            , "on_lstPlugins_row_activated": self.statusPlugin
            , "on_lstDns_button_press_event": self.dnsHandler
            , "on_cmdSpoof_activate": self.dnsRun
            , "on_cmdAbout_activate": self.showAbout
            , "on_lstDns_row_activated": self.remDns}
        self.wTree.signal_autoconnect(dic)

        #create and load the lstpassword columns
        self.lstPasswords = self.wTree.get_widget("lstPasswords")
        passwdList = gtk.ListStore(str, str, str, str)
        self.lstPasswords.set_model(passwdList)

        self.addlistColumn(self.lstPasswords,'Protocol', 0)
        self.addlistColumn(self.lstPasswords,'Hostname', 1)
        self.addlistColumn(self.lstPasswords,'User', 2)
        self.addlistColumn(self.lstPasswords,'Password', 3)

        # create and load the lstNetwork columns
        self.lstNetwork = self.wTree.get_widget("lstNetwork")
        self.networkList = gtk.ListStore(str)
        self.lstNetwork.set_model(self.networkList)
        self.addlistColumn(self.lstNetwork,'IP',0)

        
        self.lstTargets = self.wTree.get_widget("lstTargets")
        self.targetsList = gtk.ListStore(str)
        self.lstTargets.set_model(self.targetsList)
        self.addlistColumn(self.lstTargets,'IP',0)

        #create and load the lstPlugins columns
        self.lstPlugins = self.wTree.get_widget("lstPlugins")
        self.pluginsList = gtk.ListStore(bool,str,str,str)
        self.lstPlugins.set_model(self.pluginsList)
        self.addlistColumn(self.lstPlugins,'Enabled',0)
        self.addlistColumn(self.lstPlugins,'Name',1)
        self.addlistColumn(self.lstPlugins,'Desc',2)
        self.addlistColumn(self.lstPlugins,'Author',3)



        #create and load the lstDns columns
        self.lstDns = self.wTree.get_widget("lstDns")
        self.dnsList = gtk.ListStore(str,str)
        self.lstDns.set_model(self.dnsList)
        self.addlistColumn(self.lstDns,'DNS',0)
        self.addlistColumn(self.lstDns,'Ip',1)

        #load the status labels
        self.lblArp = self.wTree.get_widget("lblArp")
        self.lblSniffing = self.wTree.get_widget("lblSniffing")
        self.lblStrip = self.wTree.get_widget("lblStrip")
        self.lblDns = self.wTree.get_widget("lblDns")
        self.loadPlugins()

    def loadPlugins(self):
        for plugin in self.plugins.plugins:
            self.pluginsList.append([plugin.PROPERTY['ENABLED'],plugin.PROPERTY['NAME'],plugin.PROPERTY['DESC'], plugin.PROPERTY['AUTHOR']])

    def dnsHandler(self,widget,event):
        if event.button == 3:
            menu = gtk.Menu()
            add = gtk.MenuItem("Add")
            add.show()
            add.connect("activate",self.addDns)
            menu.append(add)
            menu.popup(None, None, None, event.button, event.time, None)

    def addDns(self,widget):
        result,domain,ip = dnsDialog().run()
        if (result == gtk.RESPONSE_OK and len(domain)>1 and len(ip)>1):
            self.dnsSpoof.addDomain(domain,ip)
            self.dnsList.append([domain,ip])

    def remDns(self, treeview, iter, *args):
        model=treeview.get_model()
        iter = model.get_iter(iter)
        dns = model.get_value(iter, 0)
        self.dnsSpoof.remDomain(dns)
        self.dnsList.remove(iter)

    def setIface(self,widget):
        result,iface = ifaceDialog().run()
        if (result == gtk.RESPONSE_OK and iface != None):
            self.iface = iface
            try:
                self.arp = arp.ARP(self.iface)
                self.sniff = sniff.sniff(self.iface, self.logger, self.plugins,self.dnsSpoof)
                self.startSniff(None)
            except(OSError):
                messageBox('Error while creating the class sniff and arp on setIface function')
                self.iface = None
        elif iface == None:
            messageBox('Error setting the iface')


class ifaceDialog:
    """This class shows the iface dialog"""

    def run(self):
        self.wTree = gtk.glade.XML(gladefile, "ifaceDlg")
        self.dlg = self.wTree.get_widget("ifaceDlg")

        self.iface = self.wTree.get_widget("cmbIface")
        self.lstIface = gtk.ListStore(str)

        interfaces = ifaces.getIfaces().interfaces

        for iface in interfaces:
            self.lstIface.append([iface.name])
            #print iface.name, iface.ip , iface.hwaddr, iface.gateway, iface.gwhwaddr

        self.iface.set_model(self.lstIface)
        cell = gtk.CellRendererText()
        self.iface.pack_start(cell)
        self.iface.add_attribute(cell,'text',0)
        self.iface.set_active(0)

        self.result = self.dlg.run()
        ifname = self.iface.get_active_text()
        self.iface = None
        self.dlg.destroy()
        for iface in interfaces:
            if iface.name == ifname:
                return self.result, iface
        return None,None

class scanDialog:
    """This class shows the scan dialog"""
		
    def run(self):
        self.wTree = gtk.glade.XML(gladefile, "scanDlg")
        self.dlg = self.wTree.get_widget("scanDlg")
        self.ip1 = self.wTree.get_widget("txtIp1")
        self.ip2 = self.wTree.get_widget("txtIp2")
        self.result = self.dlg.run()
        self.ip1 = self.ip1.get_text()
        self.ip2 = self.ip2.get_text()
        self.dlg.destroy()
        return self.result,self.ip1,self.ip2

class dnsDialog:
    """This class shows the DNS add dialog"""
		
    def run(self):
        self.wTree = gtk.glade.XML(gladefile, "dnsDlg")
        self.dlg = self.wTree.get_widget("dnsDlg")
        self.domain = self.wTree.get_widget("txtDomain")
        self.ip = self.wTree.get_widget("txtIp")
        self.result = self.dlg.run()
        self.domain = self.domain.get_text()
        self.ip = self.ip.get_text()
        self.dlg.destroy()
        return self.result,self.domain,self.ip

class messageBox:
    def __init__(self, lblmsg = '',dlgtitle = 'Error!'):
        self.wTree = gtk.glade.XML(gladefile, "msgBox")
        self.dlg = self.wTree.get_widget('msgBox')
        self.lblError = self.wTree.get_widget('lblError')
        self.dlg.set_title(dlgtitle)
        self.lblError.set_text(lblmsg)
        handlers = {'on_cmdOk_clicked':self.done}
        self.wTree.signal_autoconnect(handlers)

    def done(self,widget):
        self.dlg.destroy()


if __name__ == "__main__":
    if not os.geteuid() == 0:
        sys.exit("[-] ARPwner must run as root")
    if (os.name == "nt"):
        sys.exit("[-] ARPwner does not support windows")
    arpGui()
    gtk.main()
