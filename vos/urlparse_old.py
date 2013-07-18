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

class urlparse:
    """Break the URL into parts.

    There is a difference between the 2.5 and 2.7 version of the urlparse.urlparse command, so here I roll my own..."""

    def __init__(self, url):

        m = re.match("(^(?P<scheme>[a-zA-Z]*):)?(//(?P<netloc>[^/]*))?(?P<path>/?.*)?", url)
        if not m.group:
            return None
        self.scheme = m.group('scheme')
        self.netloc = m.group('netloc')
        self.path = m.group('path')

    def __str__(self):
        return "[scheme: %s, netloc: %s, path: %s]" % (self.scheme, self.netloc, self.path)



