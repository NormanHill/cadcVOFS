# Test the cadcCache module.

import io
import logging
import os
import unittest
from mock import Mock, MagicMock, patch

import CadcCache2 as CadcCache
import SharedLock

###import traceback
###import errno
###import shutil
###import stat
###import vos.fuse
###import time
###from vos.fuse import FuseOSError
###from mock import patch
###import thread
###from ctypes import create_string_buffer

# To run individual tests, set the value of skipTests to True, and comment
# out the @unittest.skipIf line at the top of the test to be run.
skipTests = True
testDir = "/tmp/testcache"

class IOProxyForTest(CadcCache.IOProxy):
    """
    Subclass of the CadcCache.IOProxy class. Used for both testing the
    IOProxy class and as an IOProxy object when testing the Cache class.
    """

    def getMD5(self):
	return 'd41d8cd98f00b204e9800998ecf8427e'

    def isLocked(self):
	return False

    def delNode(self, force = False):
	return

    def verifyMetaData(self, metaData):
	"""Generic test returns true"""
	return True

    def writeToBacking(self):
	return

    def readFromBacking(self, offset = None, size = None):
	return
	

class TestIOProxy(unittest.TestCase):
    """Test the IOProxy class.
    """

    def setUp(self):
        if os.path.exists(testDir):
            if os.path.isdir(testDir): 
                shutil.rmtree(testDir)
            else:
                os.remove(testDir)

    def tearDown(self):
        self.setUp()


    """
    Test the IOProxy class.
    """
    #@unittest.skipIf(skipTests, "Individual tests")
    def test_basic(self):
	"""Test the IOProxy abstract methods
	"""
	with CadcCache.Cache(testDir, 100, True) as testCache:
	    testIOProxy = CadcCache.IOProxy()
	    with self.assertRaises(NotImplementedError):
		testIOProxy.getMD5()
	    with self.assertRaises(NotImplementedError):
		testIOProxy.getSize();
	    with self.assertRaises(NotImplementedError):
		testIOProxy.isLocked()
	    with self.assertRaises(NotImplementedError):
		testIOProxy.delNode()
	    with self.assertRaises(NotImplementedError):
		testIOProxy.writeToBacking();
	    with self.assertRaises(NotImplementedError):
		testIOProxy.readFromBacking();

    def test_writeToCache(self):
	"""Test the IOProxy writeToCache method
	"""
	with CadcCache.Cache(testDir, 100, True) as testCache:
	    testIOProxy = CadcCache.IOProxy()

	    # Write to beginning of the output
	    testIOProxy.cacheFileStream = io.BufferedIOBase()
	    testIOProxy.cacheFileStream.tell = Mock(return_value = 0)
	    testIOProxy.cacheFileStream.write = Mock(return_value = 3)
	    testIOProxy.cache = testCache
	    self.assertEqual(3, testIOProxy.writeToCache("abc", 0))

	    # Write to after the beginning of the output
	    testIOProxy.cacheFileStream = io.BufferedIOBase()
	    testIOProxy.cacheFileStream.tell = Mock(return_value = 3)
	    testIOProxy.cacheFileStream.write = Mock(return_value = 3)
	    testIOProxy.cacheFileStream.seek = Mock(return_value = 1)
	    self.assertEqual(3, testIOProxy.writeToCache("abc",
		testCache.IO_BLOCK_SIZE))

	    # Test an erroneous seek to the middle of a block
	    testIOProxy.cacheFileStream = io.BufferedIOBase()
	    testIOProxy.cacheFileStream.tell = Mock(return_value = 0)
	    testIOProxy.cacheFileStream.write = Mock(return_value = 3)
	    testIOProxy.cacheFileStream.seek = Mock(return_value = 1)
            with self.assertRaises(CadcCache.CacheError) as cm:
		testIOProxy.writeToCache("abc", 3)

	    # Test a completed block write
	    testIOProxy.cacheFileStream = io.BufferedIOBase()
	    testIOProxy.cacheFileStream.tell = Mock(return_value=0)
	    testIOProxy.cacheFileStream.write = Mock(
		    return_value = testCache.IO_BLOCK_SIZE * 2)
	    testIOProxy.cacheFileStream.seek = Mock(return_value = 1)
	    buffer = bytearray(testCache.IO_BLOCK_SIZE * 2)
	    self.assertEqual(testCache.IO_BLOCK_SIZE * 2, 
		    testIOProxy.writeToCache(buffer, testCache.IO_BLOCK_SIZE))
	    # TODO assert the bitmap changed correctly - bit 0 not changed, bit
	    # 1 & 2 changed.


	    # test a subclass
	    testIOProxy = IOProxyForTest()
	    self.assertEqual(testIOProxy.getMD5(),
		    "d41d8cd98f00b204e9800998ecf8427e")
	    self.assertFalse(testIOProxy.isLocked())

    #@unittest.skipIf(skipTests, "Individual tests")
    def test_blockInfo(self):
	testIOProxy = IOProxyForTest()
	with CadcCache.Cache(testDir, 100, True) as testCache:
            testFile = testCache.open("/dir1/dir2/file", os.O_RDONLY, 
		testIOProxy)
	    self.assertEqual((0, 0), testIOProxy.blockInfo(0, 0))
	    self.assertEqual((0, 1), 
		    testIOProxy.blockInfo(0, testCache.IO_BLOCK_SIZE))
	    self.assertEqual((0, 1), 
		    testIOProxy.blockInfo(100, testCache.IO_BLOCK_SIZE))
	    self.assertEqual((2, 3), 
		    testIOProxy.blockInfo(testCache.IO_BLOCK_SIZE * 2, 
		    testCache.IO_BLOCK_SIZE * 3))
	    self.assertEqual((2, 3), 
		    testIOProxy.blockInfo(100 + testCache.IO_BLOCK_SIZE * 2, 
		    testCache.IO_BLOCK_SIZE * 3 + 100))


    #@unittest.skipIf(skipTests, "Individual tests")
    def test_readFromCache(self):
	""" Test the readFromCache method.
	"""
	with CadcCache.Cache(testDir, 100, True) as testCache:
	    # read from the start of the file.
	    testIOProxy = IOProxyForTest()
	    testIOProxy.cacheFileStream = io.BufferedIOBase()
	    testIOProxy.cacheFileStream.tell = Mock(return_value = 0)
	    testIOProxy.cacheFileStream.read = Mock(return_value = "abc")
	    testIOProxy.cacheFileStream.seek = Mock(return_value = 1)
	    testIOProxy.cache = testCache
	    buffer = testIOProxy.readFromCache(0, 10)
	    self.assertEqual("abc", buffer)
	    self.assertFalse(testIOProxy.cacheFileStream.seek.called)

	    # Read from the current position in the file
	    testIOProxy.cacheFileStream.read = Mock(return_value = "def")
	    testIOProxy.cacheFileStream.tell = Mock(return_value = 3)
	    buffer = testIOProxy.readFromCache(3, 10)
	    self.assertEqual("def", buffer)
	    self.assertFalse(testIOProxy.cacheFileStream.seek.called)

	    # Read from a different position in the file
	    testIOProxy.cacheFileStream.read = Mock(return_value = "ghi")
	    testIOProxy.cacheFileStream.tell = Mock(return_value = 3)
	    buffer = testIOProxy.readFromCache(0, 10)
	    self.assertEqual("ghi", buffer)
	    testIOProxy.cacheFileStream.seek.assert_called_once_with(0)



class TestCacheError(unittest.TestCase):
    #@unittest.skipIf(skipTests, "Individual tests")
    def test_str(self):
	e = CadcCache.CacheError("a string")
	self.assertEqual("'a string'", str(e))

class TestCadcCache(unittest.TestCase):
    """Test the CadcCache class
    """

    #@unittest.skipIf(skipTests, "Individual tests")
    def test_getFileHandle(self):
	"""Test the getFileHandle method returns the same file handle for
	   a file which is opened multiple times.
	"""
	testIOProxy = IOProxyForTest()
	testIOProxy = IOProxyForTest()
	with CadcCache.Cache(testDir, 100, True) as testCache:
            testFile = testCache.open("/dir1/dir2/file", os.O_RDONLY, 
		testIOProxy)
	    self.assertEqual(1, testFile.refCount)

            testFile2 = testCache.open("/dir1/dir2/file", os.O_RDONLY, 
		testIOProxy)
	    self.assertEqual(2, testFile.refCount)
	    self.assertTrue(testFile is testFile2)

	    testFile2.release()
	    self.assertEqual(1, testFile.refCount)

	    testFile.release()
	    self.assertEqual(0, testFile.refCount)

class TestSharedLock(unittest.TestCase):
    """Test the SharedLock class.
    """

    #@unittest.skipIf(skipTests, "Individual tests")
    def test_Exceptions(self):
	e = SharedLock.TimeoutError("timeout")
	self.assertEqual(str(e), "'timeout'")

	e = SharedLock.RecursionError("recursion")
	self.assertEqual(str(e), "'recursion'")

    #@unittest.skipIf(skipTests, "Individual tests")
    def test_simpleLock(self):
	"""Test a simple lock release sequence
	"""

	# no argument test.
	lock = SharedLock.SharedLock()
	self.assertEqual(0, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)
	lock.acquire()
	self.assertEqual(1, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)
	lock.release()
	self.assertEqual(0, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)

	# Lock with a timeout
	lock.acquire(timeout=5)
	self.assertEqual(1, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)

	# Try to acquire a lock twice. Should fail.
	with self.assertRaises(SharedLock.RecursionError) as e:
	    lock.acquire(timeout=5)
	self.assertTrue(lock.exclusiveLock is None)
	lock.release()



    #@unittest.skipIf(skipTests, "Individual tests")
    @patch('threading.current_thread')
    def test_simpleLock2(self,mock_current_thread):
	"""Test acquiring shared locks from a different thread.
	"""

	mock_current_thread.return_value = 'thread1'
	lock = SharedLock.SharedLock()
	lock.acquire()
	self.assertEqual(1, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)
	mock_current_thread.return_value = 'thread2'
	lock.acquire()
	self.assertEqual(2, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)
	lock.release()
	self.assertEqual(1, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)
	with self.assertRaises(KeyError):
	    lock.release()
	mock_current_thread.return_value = 'thread1'
	lock.release()
	self.assertEqual(0, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)


    #@unittest.skipIf(skipTests, "Individual tests")
    @patch('threading.current_thread')
    def test_exclusiveLock(self,mock_current_thread):

	# Try to acquire an exclusive lock.
	mock_current_thread.return_value = 'thread1'
	lock = SharedLock.SharedLock()
	lock.acquire(shared=False)
	self.assertEqual(lock.exclusiveLock, 'thread1')
	self.assertEqual(0, len(lock.lockersList))
	lock.release()
	self.assertEqual(0, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)

	# Get an exclusive lock and then attempt to get a shared lock with a
	# timeout.
	lock = SharedLock.SharedLock()
	lock.acquire(shared=False)
	with self.assertRaises(SharedLock.TimeoutError):
	    lock.acquire(shared=True, timeout=1)
	self.assertEqual(lock.exclusiveLock, 'thread1')
	self.assertEqual(0, len(lock.lockersList))
	lock.release()
	self.assertEqual(0, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)

	# Get a shared lock, and then attempt to get an exclusive lock with
	# a timeout
	lock.acquire(shared=True)
	self.assertEqual(1, len(lock.lockersList))
	self.assertTrue(lock.exclusiveLock is None)
	with self.assertRaises(SharedLock.TimeoutError):
	    lock.acquire(shared=False, timeout=1)


#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_constructor1(self):
#        # Constructor with a non-existing cache directory.
#        testObject = CadcCache(self.testDir, 100)
#        self.assertTrue(os.path.isdir(self.testDir))
#        self.assertTrue(os.access(self.testDir, os.R_OK | os.W_OK | os.X_OK))
#
#        # Constructor with an existing cache directory.
#        testObject = CadcCache(self.testDir, 100)
#        self.assertTrue(os.path.isdir(self.testDir))
#        self.assertTrue(os.access(self.testDir, os.R_OK | os.W_OK | os.X_OK))
#
#        self.setUp_testDirectory()
#
#        testObject = CadcCache(self.testDir, 100)
#        self.assertTrue(os.path.isdir(self.testDir))
#        self.assertTrue(os.access(self.testDir, os.R_OK | os.W_OK | os.X_OK))
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_constructor2(self):
#        # Constructor with an existing cache directory and bad permissions.
#        testObject = CadcCache(self.testDir, 100)
#        self.assertTrue(os.path.isdir(self.testDir))
#        self.assertTrue(os.access(self.testDir, os.R_OK | os.W_OK | os.X_OK))
#        os.chmod(self.testDir, stat.S_IRUSR)
#        try:
#            with self.assertRaises(CadcCache.CacheError) as cm:
#                CadcCache(self.testDir, 100)
#        finally:
#            os.chmod(self.testDir, stat.S_IRWXU)
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_constructor3(self):
#        """ Constructor with a file where the cache directory should be."""
#
#        # create the file
#        open(self.testDir, 'a').close()
#
#        with self.assertRaises(CadcCache.CacheError) as cm:
#            CadcCache(self.testDir, 100)
#
#        self.assertTrue(str(cm.exception).find("is not a directory") > 0)
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_constructor4(self):
#        """ Constructor with a file where the cache data directory should be."""
#        os.mkdir(self.testDir)
#        open(self.testDir + "/data", 'a').close()
#
#        with self.assertRaises(CadcCache.CacheError) as cm:
#            CadcCache(self.testDir, 100)
#
#        self.assertTrue(str(cm.exception).find("is not a directory") > 0)
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_constructor5(self):
#        """ Constructor with a read-only directory where the cache data directory should be."""
#        os.mkdir(self.testDir)
#        os.mkdir(self.testDir + "/data")
#        os.chmod(self.testDir + "/data", stat.S_IRUSR)
#
#        try:
#            with self.assertRaises(CadcCache.CacheError) as cm:
#                CadcCache(self.testDir, 100)
#
#            self.assertTrue(str(cm.exception).find("permission") > 0)
#        finally:
#            os.chmod(self.testDir + "/data/", stat.S_IRWXU)
#
#    def setUp_testDirectory(self):
#        directories = { "dir1", "dir2", "dir3" }
#        files = { "f1", "f2", "f3" }
#        for dir in directories:
#            os.mkdir("/".join([ self.testDir , dir ]))
#            for f in files:
#                fd = open("/".join([ self.testDir, dir, f ]),  'a')
#                fd.seek(1000)
#                fd.write ("a")
#                fd.close()
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_list_cache(self):
#        testObject = CadcCache(self.testDir, 100)
#        testObject.cache[ "/".join([ self.testDir, "aTestFile" ]) ] = \
#                { "fname": "aTestFile", "cached": False, "writting": False }
#        output = testObject.list_cache()
#        self.assertEqual(len(output), 1)
#
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_open1(self):
#        # IOProxy - getMD5 fails with ENOENT
#        class IOProxy_getMD5_ENOENT(self.IOProxyForTest):
#            def getMD5(self, path):
#                e = OSError("test failure")
#                e.errno = errno.ENOENT
#                raise e
#
#        # IOProxy - getMD5 fails with IO
#        class IOProxy_getMD5_EIO(self.IOProxyForTest):
#            def getMD5(self, path):
#                e = OSError("test failure")
#                e.errno = errno.EIO
#                raise e
#
#
#        with CadcCache(self.testDir, 100) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDONLY, ioObject)
#            fd.release()
#
#            ioObject = IOProxy_getMD5_ENOENT()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDONLY, ioObject)
#            fd.release()
#
#            ioObject = IOProxy_getMD5_ENOENT()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDWR, ioObject)
#            fd.release()
#
#            ioObject = IOProxy_getMD5_EIO()
#            with self.assertRaises(vos.fuse.FuseOSError) as cm:
#                fd = testObject.open("/dir1/dir2/file", os.O_RDWR, ioObject)
#            self.assertEqual(cm.exception.errno, errno.EIO)
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_release1(self):
#        with CadcCache(self.testDir, 100) as testObject:
#            ioObject = self.IOProxyForTest()
#            ioObject.verifyMetaData = Mock(return_value=False)
#            fd = testObject.open("/dir1/dir2/file", os.O_RDWR, ioObject)
#            fd.release()
#
#	    # Test flushnode raising an exception
#            ioObject = self.IOProxyForTest()
#            ioObject.verifyMetaData = Mock(return_value=False)
#            fd = testObject.open("/dir1/dir2/file", os.O_RDWR, ioObject)
#	    fd.flushnode = Mock(side_effect=Exception("failed"))
#	    with self.assertRaises(vos.fuse.FuseOSError) as cm:
#		fd.release()
#
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_release2(self):
#        class IOProxy_writeToBacking_slow(self.IOProxyForTest):
#            def verifyMetaData(self, path, metaData):
#                """ test returns False """
#                return False
#
#            def writeToBacking(self, fd):
#                time.sleep(4)
#                return
#
#
#        with CadcCache(self.testDir, 100) as testObject:
#            # Release a slow to write file.
#            ioObject = IOProxy_writeToBacking_slow()
#            thread.start_new_thread(self.release2_sub1, 
#                    (testObject, ioObject))
#            time.sleep(1)
#
#            ioObject2 = self.IOProxyForTest()
#            ioObject2.writeToBacking = MagicMock()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDWR, ioObject2)
#	    fd.release()
#            assert not ioObject2.writeToBacking.called, \
#                    'writeToBacking was called and should not have been'
#
#    def release2_sub1(self, testObject, ioObject):
#        fd = testObject.open("/dir1/dir2/file", os.O_RDWR, ioObject)
#        fd.release()
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_release3(self):
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = self.IOProxyForTest()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDONLY, ioObject)
#            os.close(fd.fh)
#            fd.fh = None
#            with self.assertRaises(vos.fuse.FuseOSError) as cm:
#                fd.release()
#
#
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_flushnode(self):
#        with CadcCache(self.testDir, 100) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDONLY, ioObject)
#            fd.flushnode(None, fd.fh)
#            fd.release()
#
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDWR, ioObject)
#            fd.flushnode(None, fd.fh)
#
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_add_to_cache(self):
#        with CadcCache(self.testDir, 100) as testObject:
#            testObject.cache_dir = "/nosuchdir"
#            testObject.cache_data_dir = "/nosuchdir"
#            #with self.assertRaises(FuseOSError):
#            #    testObject.add_to_cache("/")
#            # This should cause a permission denied
#            testObject.cache_dir = "/proc/1/fd/afile/bfile/"
#            testObject.data_dir = "/proc/1/fd/afile/bfile/data"
#            with self.assertRaises(FuseOSError):
#                testObject.add_to_cache("nosuchpath")
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_fsync1(self):
#        # fsync Does nopthing on read-only cache.
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDONLY, ioObject)
#            fd.fsync(None, False, fd.fh)
#            fd.release()
#
#        # fsync returns an error
#        with CadcCache(self.testDir, 100, readonly = False) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDWR, ioObject)
#            os.close(fd.fh)
#            fd.fsync(None, False, fd.fh)
#
#        # fsync errors when the file is locked
#        with CadcCache(self.testDir, 100, readonly = False) as testObject:
#            ioObject = self.IOProxyForTest()
#            ioObject.verifyMetaData = MagicMock(return_value=False)
#            ioObject.isLocked = MagicMock(return_value=True)
#            fd = testObject.open("/dir1/dir2/file", os.O_RDONLY, ioObject)
#            with self.assertRaises(FuseOSError):
#                fd.fsync(None, False, fd.fh)
#            fd.release()
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_is_cached(self):
#        # fsync Does nopthing on read-only cache.
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDONLY, ioObject)
#            self.assertFalse (fd.is_cached())
#            fd.release()
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_metaData(self):
#        # Just test the error from os.access as the rest of the method is
#        # already tested.
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#            fd = testObject.open("/dir1/dir2/file", os.O_RDONLY, ioObject)
#            with self.assertRaises(FuseOSError):
#                fd.metaData("/etc/shadow")
#            fd.release()
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_read1(self):
#        # Do a simple read of a file.
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#	    fd = testObject.open("dir1/dir1/file", os.O_RDONLY, ioObject)
#            try:
#		buffer = fd.read(100, 0)
#            finally:
#                fd.release()
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_read2(self):
#        """ Cause an error that the cached file is not in the cache."""
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#	    fd = testObject.open("dir1/dir1/file", os.O_RDONLY, ioObject)
#	    oldPath = fd.path
#            try:
#		fd.path = "somethingelse"
#		with self.assertRaises(FuseOSError):
#		    buffer = fd.read(100, 0)
#		fd.path = oldPath
#            finally:
#		fd.path = oldPath
#                fd.release()
#
## This test works in isolation, but doesn't work if other tests are running.
## The release needs code to wait until all running threads have exited.
#    #@unittest.skipIf(skipTests, "Individual tests")
#    @unittest.skipIf(True, "Individual tests")
#    def test_read3(self):
#	""" Do a read in a thread and then a second read that has to wait
#	    for the first read"""
#
#        class IOProxy_slowReadFromBacking(self.IOProxyForTest):
#	    def __init__(self):
#		super(IOProxy_slowReadFromBacking, self).__init__()
#		self.getMD5Count = 0
#		self.callCount = 0
#            def readFromBacking(self, offset = None, size = None):
#		self.callCount += 1
#		infs = open("/dev/urandom", "r+b")
#		thisOffset = 0
#		try:
#		    for i in range (1, 100):
#			buffer = infs.read(65536)
#			self.writeCache(buffer, thisOffset)
#			thisOffset = thisOffset + len(buffer)
#			time.sleep(.1)
#		finally:
#		    infs.close()
#	    def verifyMetaData(self, path, metaData):
#		return False
#	    def getMD5(self, path):
#		self.getMD5Count += 1
#		if (self.getMD5Count <= 2):
#		    return 'e41d8cd98f00b204e9800998ecf8427e'
#		else:
#		    return 'd41d8cd98f00b204e9800998ecf8427e'
#
#
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = IOProxy_slowReadFromBacking()
#	    fd = testObject.open("dir1/dir1/file", os.O_RDONLY, ioObject)
#            try:
#		buffer = fd.read(100, 0)
#		fd.get_md5_db = Mock(
#		    return_value={'md5': 'd41d8cd98f00b204e9800998ecf8427e' })
#
#		# The read stream should be still running in the background 
#		# because of the sleep in the IOProxy_slowReadFromBacking 
#		# readFromBacking method. A read futher on in the file should 
#		# wait for the read to get here and return.
#		self.assertEqual(ioObject.callCount, 1)
#		buffer = fd.read(100, 10^6)
#	    except Exception as e:
#		raise e
#            finally:
#                fd.release()
#
#
#
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_load_into_cache(self):
#        # Load a file into cache
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#	    fd = testObject.open("dir1/dir1/file", os.O_RDONLY, ioObject)
#            fd.get_md5_db = Mock(
#		    return_value={'md5': 'd41d8cd98f00b204e9800998ecf8427e' })
#            try:
#		buffer = fd.load_into_cache("dir1/dir1/file")
#            finally:
#                fd.release()
#
#	# Simulate an incorrect md5sum
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#	    fd = testObject.open("dir1/dir1/file", os.O_RDONLY, ioObject)
#            fd.get_md5_db = Mock(
#		    return_value={'md5': 'wrong-md5' })
#            try:
#		with self.assertRaises(FuseOSError):
#		    fd.load_into_cache("dir1/dir1/file")
#            finally:
#                fd.release()
#
#    @unittest.skipIf(skipTests, "Individual tests")
#    def test_load_into_cache2(self):
#        class IOProxy_slowReadFromBacking(self.IOProxyForTest):
#            def readFromBacking(self, offset = None, size = None):
#		infs = open("/dev/urandom", "rb")
#		thisOffset = 0
#		bufSize = 65536
#		buf = create_string_buffer(bufSize)
#		try:
#		    for i in range (1, 100):
#			buffer = infs.read(65536)
#			if (i != 50):
#			    self.writeCache(buffer, thisOffset)
#			thisOffset = thisOffset + len(buffer)
#			time.sleep(.1)
#		finally:
#		    infs.close()
#	    def verifyMetaData(self, path, metaData):
#		return False
#	    def getMD5(self, path):
#		return 'd41d8cd98f00b204e9800998ecf8427e'
#        # Load a file into cache
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = IOProxy_slowReadFromBacking()
#	    fd = testObject.open("dir1/dir1/file", os.O_RDONLY, ioObject)
#            fd.get_md5_db = Mock(
#		    return_value={'md5': 'd41d8cd98f00b204e9800998ecf8427e' })
#            try:
#		fd.load_into_cache("dir1/dir1/file")
#            finally:
#                fd.release()
#
#	    fd.flushnode = Mock(side_effect=Exception("failed"))
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = self.IOProxyForTest()
#	    ioObject.readFromBacking = Mock(side_effect=OSError("failed"))
#	    fd = testObject.open("dir1/dir1/file", os.O_RDONLY, ioObject)
#            fd.get_md5_db = Mock(
#		    return_value={'md5': 'd41d8cd98f00b204e9800998ecf8427e' })
#            try:
#		with self.assertRaises(FuseOSError):
#		    fd.load_into_cache("dir1/dir1/file")
#            finally:
#                fd.release()
#
#    #@unittest.skipIf(skipTests, "Individual tests")
#    def test_write1(self):
#	print "one"
#        # Do a simple write To a read-only cache. Should return 0 bytes.
#        with CadcCache(self.testDir, 100, readonly = True) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#	    fd = testObject.open("dir1/dir1/file", os.O_RDWR, ioObject)
#	    buffer="abcd"
#            try:
#		self.assertEqual(0, fd.write(buffer, 4, 0))
#            finally:
#                fd.release()
#
#        # Do a simple write To a read-only cache. Should return 4 bytes.
#	# This file looks like it doesn't exist
#	print "two"
#        with CadcCache(self.testDir, 100, readonly = False) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#	    fd = testObject.open("dir1/dir1/file", os.O_RDWR, ioObject)
#	    buffer="abcd"
#            try:
#		self.assertEqual(4, fd.write(buffer, 4, 0))
#            finally:
#                fd.release()
#
#	    self.assertEqual(4, os.stat(testObject.data_dir + 
#		    "/dir1/dir1/file").st_size)
#
#        # Do a simple write To a read-only cache. Should return 4 bytes.
#	# This file looks like it does exist.
#	print "three"
#        with CadcCache(self.testDir, 100, readonly = False) as testObject:
#            ioObject = TestCadcCache.IOProxyForTest()
#	    fd = testObject.open("dir1/dir1/file2", os.O_RDWR, ioObject)
#	    buffer="abcd"
#            try:
#		self.assertEqual(4, fd.write(buffer, 4, 100))
#            finally:
#                fd.release()
#
#	    self.assertEqual(4, os.stat(testObject.data_dir + 
#		    "/dir1/dir1/file").st_size)

logging.getLogger('CadcCache').setLevel(logging.DEBUG)
logging.getLogger('CadcCache').addHandler(logging.StreamHandler())

suite1 = unittest.TestLoader().loadTestsFromTestCase(TestIOProxy)
suite2 = unittest.TestLoader().loadTestsFromTestCase(TestCadcCache)
suite3 = unittest.TestLoader().loadTestsFromTestCase(TestCacheError)
suite4 = unittest.TestLoader().loadTestsFromTestCase(TestSharedLock)
alltests = unittest.TestSuite([suite1, suite2, suite3, suite4])
unittest.TextTestRunner(verbosity=2).run(alltests)

