import os
import shutil
import unittest
from vos import vofs
from mock import Mock, MagicMock, patch
from vos.fuse import FuseOSError
from vos.CadcCache import Cache, CacheRetry, CacheAborted, FileHandle
from errno import EIO


class Object(object):
    pass

class TestVOFS(unittest.TestCase):
    testMountPoint = "/tmp/testfs"
    testCacheDir = "/tmp/testCache"
    def initOpt(self):
        opt = Object
        opt.readonly = False
        return opt

    def setUp(self):
        global opt
        opt = self.initOpt()
        if os.path.exists(self.testCacheDir):
            shutil.rmtree(self.testCacheDir)

    def tearDown(self):
        self.setUp()

    def testWrite1(self):
        """ Write to a read-only or locked file"""
        testfs = vofs.VOFS(self.testMountPoint, self.testCacheDir, opt)
        fileHandle = vofs.FileHandle(None)
        fileHandle.readOnly = True
        # Write some data at the start of the file. File is read only so it
        # returns 0
        with self.assertRaises(FuseOSError):
            testfs.write( "/dir1/dir2/file", "abcd", 4, 0, fileHandle)


    def testWrite2(self):
        """ Write to a read-only file system"""
        opt.readonly = True
        testfs = vofs.VOFS(self.testMountPoint, self.testCacheDir, opt)
        fileHandle = vofs.FileHandle(None)
        fileHandle.readOnly = False
        # Write some data at the start of the file.
        self.assertEqual(testfs.write( "/dir1/dir2/file", "abcd", 4, 0,
                fileHandle), 0)

    def testWrite3(self):
        """Test a successfull write."""

        testfs = vofs.VOFS(self.testMountPoint, self.testCacheDir, opt)
        fileHandle = vofs.FileHandle(Object())
        fileHandle.cacheFileHandle.write = Mock()
        fileHandle.cacheFileHandle.write.return_value = 4
        self.assertEqual(testfs.write( "/dir1/dir2/file", "abcd", 4, 0,
                fileHandle), 4)
        fileHandle.cacheFileHandle.write.return_value = 4
        fileHandle.cacheFileHandle.write.assert_called_once_with("abcd", 4, 0)

        fileHandle.cacheFileHandle.write.call_count = 0
        self.assertEqual(testfs.write( "/dir1/dir2/file", "abcd", 4, 2048,
                fileHandle), 4)
        fileHandle.cacheFileHandle.write.return_value = 4
        fileHandle.cacheFileHandle.write.assert_called_once_with("abcd", 4, 2048)

    def testWrite4(self):
        """Test a timout during write"""

        testfs = vofs.VOFS(self.testMountPoint, self.testCacheDir, opt)
        fileHandle = vofs.FileHandle(Object())
        fileHandle.cacheFileHandle.write = Mock()
        fileHandle.cacheFileHandle.write.side_effect = CacheRetry("fake")
        with self.assertRaises(FuseOSError):
            testfs.write( "/dir1/dir2/file", "abcd", 4, 2048, fileHandle)

    def testRead1(self):
        testfs = vofs.VOFS(self.testMountPoint, self.testCacheDir, opt)

        # Read with a null file handle.
        with self.assertRaises(FuseOSError):
            testfs.read( "/dir1/dir2/file", 4, 2048)

        # Read with a timeout.
        fileHandle = vofs.FileHandle(Object())
        fileHandle.cacheFileHandle.read = Mock()
        fileHandle.cacheFileHandle.read.side_effect = CacheRetry("fake")
        with self.assertRaises(FuseOSError):
            testfs.read( "/dir1/dir2/file", 4, 2048, fileHandle)

        # Read with success.
        fileHandle = vofs.FileHandle(Object())
        fileHandle.cacheFileHandle.read = Mock()
        fileHandle.cacheFileHandle.read.return_value = "abcd"
        self.assertEqual( testfs.read( "/dir1/dir2/file", 4, 2048, fileHandle),
                "abcd")


class TestMyIOProxy(unittest.TestCase):
    def testWriteToBacking(self):
        # Submit a write request for the whole file.
        with Cache(TestVOFS.testCacheDir, 100, timeout=1) as testCache:
            client = Object
            client.copy = Mock()
            vofsObj = Object
            node = Object
            node.uri = "vos:/dir1/dir2/file"
            node.props={"MD5": 12345}
            vofsObj.getNode = Mock(return_value=node)
            testProxy = vofs.MyIOProxy(client, vofsObj)
            path = "/dir1/dir2/file"
            with FileHandle(path, testCache, testProxy) as \
                    testFileHandle:
                testProxy.cacheFile = testFileHandle
                self.assertEqual(testProxy.writeToBacking(), 12345)
            client.copy.assert_called_once_with( testCache.dataDir + 
                    "/dir1/dir2/file", node.uri)

    def testReadFromBacking(self):
        callCount = [0]
        def mock_read(block_size):
            callCount[0] += 1
            if callCount[0] == 1:
                return "1234"
            else:
                return None

        with Cache(TestVOFS.testCacheDir, 100, timeout=1) as testCache:
            client = Object
            streamyThing = Object()
            client.open = Mock(return_value = streamyThing)
            client.close = Mock()
            client.read = Mock(side_effect = mock_read)
            testProxy = vofs.MyIOProxy(client, None)
            path = "/dir1/dir2/file"
            with FileHandle(path, testCache, testProxy) as \
                    testFileHandle:
                testProxy.writeToCache = Mock(return_value = 4)
                testProxy.cacheFile = testFileHandle
                testProxy.cacheFile.readThread = Object()
                testProxy.cacheFile.readThread.aborted = False
                try:

                    # Submit a request for the whole file
                    testProxy.readFromBacking()
                    client.open.assert_called_once_with(path, mode=os.O_RDONLY, 
                            view="data", size=None, range=None)
                    self.assertEqual(client.close.call_count, 1)
                    self.assertEqual(client.read.call_count, 2)

                    # Submit a range request
                    client.open.reset_mock()
                    client.close.reset_mock()
                    client.read.reset_mock()
                    callCount[0] = 0
                    testProxy.readFromBacking(100,200)
                    client.open.assert_called_once_with(path, mode=os.O_RDONLY, 
                            view="data", size=100, range=(100,200))
                    self.assertEqual(client.close.call_count, 1)
                    self.assertEqual(client.read.call_count, 2)

                    # Submit a request which gets aborted.
                    client.open.reset_mock()
                    client.close.reset_mock()
                    client.read.reset_mock()
                    callCount[0] = 0
                    testProxy.writeToCache.side_effect = CacheAborted("aborted")
                    testProxy.readFromBacking(100,200)
                    client.open.assert_called_once_with(path, mode=os.O_RDONLY, 
                            view="data", size=100, range=(100,200))
                    self.assertEqual(client.close.call_count, 1)
                    self.assertEqual(client.read.call_count, 1)

                finally:
                    testProxy.cacheFile.readThread = None


suite1 = unittest.TestLoader().loadTestsFromTestCase(TestVOFS)
suite2 = unittest.TestLoader().loadTestsFromTestCase(TestMyIOProxy)
alltests = unittest.TestSuite([suite1, suite2])
unittest.TextTestRunner(verbosity=2).run(alltests)


