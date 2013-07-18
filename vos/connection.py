"""A set of Python Classes for connecting to and interacting with a VOSpace service.

   Connections to VOSpace are made using a SSL X509 certificat which is stored in a .pem file.
   The certificate is supplied by the user or by the CADC credential server

"""

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
import xml.etree.ElementTree as ET


from __version__ import version


# set a 1 MB buffer to keep the number of trips
# around the IO loop small

BUFSIZE = 8388608


# consts for dealing with transient errors
MAX_RETRY_DELAY = 128; # maximum delay between retries
DEFAULT_RETRY_DELAY = 30; # start delay between retries when Try_After not specified by server
MAX_RETRY_TIME = 900; # maximum time for retries before giving up...

SERVER = os.getenv('VOSPACE_WEBSERVICE', 'www.canfar.phys.uvic.ca')
CADC_GMS_PREFIX = "ivo://cadc.nrc.ca/gms#"

class Connection:
    """Class to hold and act on the X509 certificate"""

    def __init__(self, certfile=None):
        """Setup the Certificate for later usage

        cerdServerURL -- the location of the cadc proxy certificate server
        certfile      -- where to store the certificate, if None then ${HOME}/.ssl or a temporary filename

        The user must supply a valid certificate.
        """


        ## allow anonymous access if no certfile is specified...
        if certfile is not None and not os.access(certfile, os.F_OK):
            raise EnvironmentError(
                errno.EACCES, 
                "No certificate file found at %s\n (Perhaps use getCert to pull one)" % (certfile))
        self.certfile = certfile



    def getConnection(self, url):
        """Create an HTTPSConnection object and return.  Uses the client certificate if None given.

        uri  -- a VOSpace uri (vos://cadc.nrc.ca~vospace/path)
        certFilename -- the name of the certificate pem file.
        """
        logging.debug("parsing url: %s" %(url))
        parts = urlparse(url)
        logging.debug("Got: %s " % ( str(parts)))
        ports = {"http": 80, "https": 443}
        certfile = self.certfile
        logging.debug("Trying to connect to %s://%s using %s" % (parts.scheme,parts.netloc,certfile))

        try:
            if parts.scheme=="https":
                connection = httplib.HTTPSConnection(parts.netloc,key_file=certfile,cert_file=certfile,timeout=60)
            else:
                connection = httplib.HTTPConnection(parts.netloc,timeout=60)
        except httplib.NotConnected as e:
            logging.error("HTTP connection to %s failed \n" % (parts.netloc))
            logging.error("%s \n" % (str(e)))
            raise OSError(errno.ENTCONN, "VOSpace connection failed", parts.netloc)

        if logging.getLogger('root').getEffectiveLevel() == logging.DEBUG :
            connection.set_debuglevel(1)

        ## Try to open this connection. 
        timestart = time.time()
        logging.debug("Opening the connection")
        while True:
            try:
                connection.connect()
            except httplib.HTTPException as e:
                logging.critical("%s" % (str(e)))
                logging.critical("Retrying connection for 30 seconds")
                if time.time() - timestart > 1200:
                    raise e
            except Exception as e:
                logging.debug(str(e))
                ex = IOError()
                ex.errno = errno.ECONNREFUSED
                ex.strerror = str(e)
                ex.filename = parts.netloc
                raise ex
            break

        #logging.debug("Returning connection " )
        return connection


