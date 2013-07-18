import connection_manager
import unittest
import httplib

import os

HOME = os.getenv('HOME','')
PROXY_DIR=os.path.join(HOME,'.ssl')
PROXY_FILE=os.path.join(PROXY_DIR,'cadcproxy.pem')
SERVER="www.canfar.phys.uvic.ca"
HTTPS_SERVER='https://'+SERVER
HTTP_SERVER='http://'+SERVER

class TestConnectionManager(unittest.TestCase):

    def setUp(self):
        self.certfile = PROXY_FILE
        self.server = SERVER


    def test_get_secure_connection(self):
        connection = connection_manager.get_connection(HTTPS_SERVER,
                                                        PROXY_FILE)
        self.assertIsInstance(connection,httplib.HTTPSConnection)

    def test_get_connection(self):
        connection = connection_manager.get_connection(HTTP_SERVER,
                                                       None)
        self.assertIsInstance(connection, httplib.HTTPConnection)

    def test_failed_secure(self):
        self.assertRaises(IOError, connection_manager.get_connection,
                          HTTPS_SERVER, None)


if __name__ == '__main__':
    unittest.main()
