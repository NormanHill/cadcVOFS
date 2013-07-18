import copy
import errno
import hashlib
import html2text
import httplib
import logging
import math
import mimetypes
import os
import random
import re
import ssl
import stat
import string
import sys
import time
import threading
import urllib
import urllib2
from urlparse import urlparse
import xml.etree.ElementTree as ET
from settings import MAX_RETRY_TIME, MAX_RETRY_DELAY, RETRY_DELAY
from settings import CONNECTION_TIME_OUT
from __version__ import version


class VOFile:
    """
    A class for managing http connecctions

    Attributes:
    maxRetries - maximum number of retries when transient errors encountered. When set
    too high (as the default value is) the number of retries are time limitted (max 15min)
    maxRetryTime - maximum time to retry for when transient errors are encountered
    """
   
    ### if we get one of these codes, retry the command... ;-(
    retryCodes = (503, 408, 504, 402, 412) 

    def __init__(self, URL, certfile=None, method='GET', size=None, followRedirect=True,
                 header=None,
                 data=None ):


        self.URL = URL
        self.certfile = certfile
        self.method = method
        self.size = size
        self.followRedirect = followRedirect
        self.header = header
        self.data = data


        self.closed = True
        self.resp = 503

        self.timeout = -1
        self.size = size
        self.maxRetries = 10000
        self.maxRetryTime = MAX_RETRY_TIME
        self.name = os.path.basename(self.URL)

        self._fpos = 0

        # initial values for retry parameters
        self.currentRetryDelay = RETRY_DELAY
        self.totalRetryDelay = 0
        self.retries = 0

        self._open()

    def tell(self):
        return self._fpos

    def seek(self, offset, loc=os.SEEK_SET):
        if loc == os.SEEK_CUR:
            self._fpos += offset
        elif loc == os.SEEK_SET:
            self._fpos = offset
        elif loc == os.SEEK_END:
            self._fpos = self.size - offset
        return

    def close(self, code=(200, 201, 202, 206, 302, 303, 503, 416, 402, 408, 412, 504)):
        """close the connection"""
        #logging.debug("inside the close")
        if self.closed:
            return
        #logging.debug("Closing connection")
        try:
            if self.transEncode is not None:
                self.http_conn.send('0\r\n\r\n')
            self.resp = self.http_conn.getresponse()
            time.sleep(0.1)
            self.http_conn.close()
        except ssl.SSLError as e:
            raise IOError(errno.EAGAIN, str(e))
        except Exception as e:
            raise IOError(errno.ENOTCONN, str(e))
        self.closed = True
        logging.debug("Connection closed")
        return self.checkstatus(codes=code)

    def checkstatus(self, codes=(200, 201, 202, 206, 302, 303, 503, 416, 416, 402, 408, 412, 504)):
        """check the response status"""
        msgs = { 404: "Node Not Found",
                 401: "Not Authorized",
                 409: "Conflict",
                 408: "Connection Timeout"}
        errnos = { 404: errno.ENOENT,
                   401: errno.EACCES,
                   409: errno.EEXIST,
                   408: errno.EAGAIN }
        logging.debug("status %d for URL %s" % (self.resp.status, self.URL))
        if self.resp.status not in codes:
            logging.debug("Got status code: %s for %s" % (self.resp.status, self.URL))
            msg = self.resp.read()
            if msg is not None:
                msg = html2text.html2text(msg, self.URL).strip()
            logging.debug("Error message: %s" % (msg))
            if self.resp.status in errnos.keys():
                if msg is None or len(msg) == 0:
                    msg = msgs[self.resp.status]
                if self.resp.status == 401 and self.certfile is None:
                    msg += " using anonymous access "
                raise IOError(errnos[self.resp.status], msg, self.URL)
            raise IOError(self.resp.status, msg, self.URL)
        self.size = self.resp.getheader("Content-Length", 0)
        return True

    
    def connection(self, url ):
        """Create an HTTPSConnection object and return.  
        Uses the client certificate if None given.
    
        uri  -- a VOSpace uri (vos://cadc.nrc.ca~vospace/path)
        
        returns HTTP(S)Connection object
        """
    
        logging.debug("Creating a connection to %s" % ( url))
    
        parts = urlparse(url)
        
        if parts.scheme=="https":
            connection = httplib.HTTPSConnection(parts.netloc,
                                                 key_file=self.certfile,
                                                 cert_file=self.certfile,
                                                 timeout=CONNECTION_TIME_OUT)
        else:
            connection = httplib.HTTPConnection(parts.netloc,
                                                timeout=CONNECTION_TIME_OUT)
        # Try to open this connection.  Keep re-try if connection fails at first. 
        timestart = time.time()

        while time.time() - timestart < MAX_RETRY_TIME :
            try:
                connection.connect()
                break
            except ssl.SSLError as ex:
                logging.critical(str(ex))
                raise IOError(errno.ECONNREFUSED,
                              ex.strerror,
                              url)
            except Exception as ex:
                # if we could detect interactivity then could ask for new
                # cert here!
                logging.critical("possible network error: "
                                 "retrying every %ds for %ds" 
                                 % ( RETRY_DELAY, MAX_RETRY_TIME ) )
                time.sleep(RETRY_DELAY)

        if connection.sock is None:
            raise IOError(errno.ECONNREFUSED, 
                          'connection failed',
                          parts.netloc)

        logging.debug("Returning connection")
        return connection

    def _open(self, bytes=None):
        """Open a connection to the given URL"""
        logging.debug("Opening %s (%s)" % (self.URL, self.method))

        http_conn = self.connection(self.URL)
        self.closed = False

        http_conn.putrequest(self.method, self.URL)

        userAgent = 'vos ' + version
        if "mountvofs" in sys.argv[0]:
            userAgent = 'vofs ' + version
        http_conn.putheader("User-Agent", userAgent)
        self.transEncode = None

        #logging.debug("sending headers for file of size: %s " % (str(self.size)))
        if self.method in ["PUT"]:
            try:
                self.size = int(self.size)
                http_conn.putheader("Content-Length", self.size)
            except TypeError as e:
                self.size = None
                self.transEncode = "chunked"
                http_conn.putheader("Transfer-Encoding", 'chunked')
        elif self.method in ["POST", "DELETE"]:
            self.size = None
            http_conn.putheader("Transfer-Encoding", 'chunked')
            self.transEncode = "chunked"
        if self.method in ["PUT", "POST", "DELETE"]:
            contentType = "text/xml"
            if self.method == "PUT":
                ext = os.path.splitext(urllib.splitquery(self.URL)[0])[1]
                #logging.debug("Got extension %s" % (ext))
                if ext in [ '.fz', '.fits', 'fit']:
                    contentType = 'application/fits'
                else:
                    contentType = mimetypes.guess_type(self.URL)[0]
                    #logging.debug("Guessed content type: %s" % (contentType))
            if contentType is not None:
                #logging.debug("Content-Type: %s" % str(contentType))
                http_conn.putheader("Content-Type", contentType)
        if bytes is not None and self.method == "GET" :
            #logging.debug("Range: %s" % (bytes))
            http_conn.putheader("Range", bytes)
        http_conn.putheader("Accept", "*/*")
        http_conn.putheader("Expect", "100-continue")
        http_conn.endheaders()
        self.http_conn = http_conn

    def read(self, size=None):
        """return size bytes from the connection response"""
        #logging.debug("Starting to read file by closing http(s) connection")
        if not self.closed:
            self.close()
        
        bytes = None
        #if size != None:
        #    bytes = "bytes=%d-" % ( self._fpos)
        #    bytes = "%s%d" % (bytes,self._fpos+size)
        #self.open(self.url,bytes=bytes,method="GET")
        #self.close(code=[200,206,303,302,503,404,416])
        if self.resp.status == 416:
            return ""
        # check the most likely response first
        if self.resp.status == 200:
            buff = self.resp.read(size)
            #logging.debug(buff)
            return buff
        if self.resp.status == 206:
            buff = self.resp.read(size)
            self._fpos += len(buff)
            #logging.debug("left file pointer at: %d" % (self._fpos))
            return buff
        elif self.resp.status == 404:
            raise IOError(errno.ENFILE, self.resp.read())
        elif self.resp.status == 303 or self.resp.status == 302:
            self.URL = self.resp.getheader('Location', None)
            logging.debug("Got redirect URL: %s" % (self.URL))
            if not self.URL:
                raise IOError(errno.ENOENT, "No Location on redirect", self.URL)
            if self.followRedirect:
                self.method="GET"
                self._open()
                return self.read(size)
            else:
                return self.URL
        elif self.resp.status in VOFile.retryCodes:
            ## try again in Retry-After seconds or fail
            logging.error("Got %d: server busy on %s" % (self.resp.status, self.URL))
            msg = self.resp.read()
            if msg is not None:
                msg = html2text.html2text(msg, self.URL).strip()
 	    else:
	        msg = "No Message Sent"
            logging.error("Message:  %s" % (msg))
            try:
	        ### see if there is a Retry-After in the head...
                ras = int(self.resp.getheader("Retry-After", 5))
            except:
                ras = self.currentRetryDelay
                if (self.currentRetryDelay * 2) < MAX_RETRY_DELAY:
                    self.currentRetryDelay = self.currentRetryDelay * 2
                else:
                    self.currentRetryDelay = MAX_RETRY_DELAY
        else:
            # line below can be removed after we are sure all codes
            # are caught
            raise IOError(self.resp.status, 
                          ( "unexpected server response %s (%d)" % 
                            (self.resp.reason, self.resp.status), self.URL ) )
        
        if (( self.retries < self.maxRetries ) 
            and ( self.totalRetryDelay < self.maxRetryTime )):
            logging.error("retrying in %d seconds" % (ras))
            self.totalRetryDelay = self.totalRetryDelay + ras
            self.retries = self.retries + 1
            time.sleep(int(ras))                          
            
            self._open()
            self.read(size)
        else:
            raise IOError(self.resp.status, 
                          ("failed to connect to server after " 
                           "multiple attempts %s (%d)" 
                           % (self.resp.reason, self.resp.status)), 
                          self.URL)

    def write(self, buf):
        """write buffer to the connection"""
        if not self.http_conn or self.closed:
            raise OSError(errno.ENOTCONN, "no connection for write", self.URL)
        ### If we are sending chunked then we need to frame the transfer
        if self.transEncode is not None:
            self.http_conn.send('%X\r\n' % len(buf))
            self.http_conn.send(buf + '\r\n')
        else:
            self.http_conn.send(buf)
        return len(buf)

