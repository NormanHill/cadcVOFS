# set a 1 MB buffer to keep the number of trips
# around the IO loop small
BUFSIZE = 8388608


# consts for dealing with transient errors
MAX_RETRY_DELAY = 128; # maximum delay between retries
RETRY_DELAY = 30; # delay between retries when Try_After not specified by server
MAX_RETRY_TIME = 900; # max time for retries before abort
CONNECTION_TIME_OUT = 60 ## max time to wait for http response

import os
SERVER = os.getenv('VOSPACE_WEBSERVICE', 'www.canfar.phys.uvic.ca')


CADC_GMS_PREFIX = "ivo://cadc.nrc.ca/gms#"
