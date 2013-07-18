"""A set of Python Classes for connecting to and interacting with a VOSpace service.

   Connections to VOSpace are made using a SSL X509 certificat which is stored in a .pem file.
   The certificate is supplied by the user or by the CADC credential server

"""

import httplib
import ssl
import logging
import time
from urlparse import urlparse
import errno

# consts for dealing with transient errors
CONNECTION_TIME_OUT = 60
RETRY_DELAY = 30 # delay between retries 
MAX_RETRY_TIME = 900 # maximum time for retries before giving up...

def get_connection(url, certfile):
    """Create an HTTPSConnection object and return.  
    Uses the client certificate if None given.
    
    uri  -- a VOSpace uri (vos://cadc.nrc.ca~vospace/path)
    
    returns HTTP(S)Connection object
    """
    
    logging.debug("Creating a connection to %s" % ( url))
    
    parts = urlparse(url)
    
    if parts.scheme=="https":
        connection = httplib.HTTPSConnection(parts.netloc,
                                             key_file=certfile,
                                             cert_file=certfile,
                                             timeout=CONNECTION_TIME_OUT)
    else:
        connection = httplib.HTTPConnection(parts.netloc,
                                            timeout=CONNECTION_TIME_OUT)

    ## Try to open this connection.  Keep re-try if connection fails at first. 
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
            ## if we could detect interactivity then could ask for new
            ## cert here!
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


