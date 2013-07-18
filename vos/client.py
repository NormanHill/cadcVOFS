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
from urlparse import urlparse
import xml.etree.ElementTree as ET


import connection_manager
from vofile import VOFile 
from node import Node


from settings import SERVER, BUFSIZE


from __version__ import version


class Client:
    """The Client object does the work"""

    VOServers = {'cadc.nrc.ca!vospace': SERVER,
               'cadc.nrc.ca~vospace': SERVER}

    VOTransfer = '/vospace/synctrans'
    VOProperties = '/vospace/nodeprops'
    VO_HTTPGET_PROTOCOL = 'ivo://ivoa.net/vospace/core#httpget'
    VO_HTTPPUT_PROTOCOL = 'ivo://ivoa.net/vospace/core#httpput'
    VO_HTTPSGET_PROTOCOL = 'ivo://ivoa.net/vospace/core#httpsget'
    VO_HTTPSPUT_PROTOCOL = 'ivo://ivoa.net/vospace/core#httpsput'
    DWS = '/data/pub/'

    def __init__(self, 
                 certFile=os.path.join(os.getenv('HOME'), 
                                       '.ssl/cadcproxy.pem'),
                 rootNode=None, 
                 conn=None, 
                 archive='vospace', 
                 cadc_short_cut=False):
        """This could/should be expanded to set various defaults

        certFile: CADC proxy certficate location.
        rootNode: the base of the VOSpace for uri references.
        conn: a connection pool object for this Client
        archive: the name of the archive to associated with GET requests
        cadc_short_cut: if True then request data web service urls
        
        """
        if certFile is not None and not os.access(certFile, os.F_OK):
            ### can't get this certfile
            #logging.debug("Failed to access certfile %s " % (certFile))
            #logging.debug("Using anonymous mode, try getCert if you want to use authentication")
            certFile = None
        if certFile is None:
            self.protocol = "http"
        else:
            self.protocol = "https"
        self.certfile = certFile
        if conn is None:
            conn = connection_manager
        self.VOSpaceServer = "cadc.nrc.ca!vospace"
        self.rootNode = rootNode
        self.archive = archive
        self.nodeCache={}
        self.cadc_short_cut = cadc_short_cut
        return

    def copy(self, src, dest, sendMD5=False):
        """copy to/from vospace"""

        checkSource = False
        if src[0:4] == "vos:":
            srcNode = self.getNode(src)
            srcSize = srcNode.attr['st_size']
            srcMD5 = srcNode.props.get('MD5', 'd41d8cd98f00b204e9800998ecf8427e')
            fin = self.open(src, os.O_RDONLY, view='data')
            fout = open(dest, 'w')
            checkSource = True
        else:
            srcSize = os.lstat(src).st_size
            fin = open(src, 'r')
            fout = self.open(dest, os.O_WRONLY, size=srcSize)

        destSize = 0
        md5 = hashlib.md5()
        ## wrap the read statements in a try/except repeat
        ## if you get this far into copy then the node exists
        ## and the error is likely a transient timeout issue
        try:
            while True:
                buf = fin.read(BUFSIZE)
                if len(buf) == 0:
                    break
                fout.write(buf)
                md5.update(buf)
                destSize += len(buf)
        except IOError as e:
            logging.error(str(e))
            return self.copy(src,dest,sendMD5=sendMD5)
        finally:
            fout.close()
            fin.close()


        if checkSource:
            if srcNode.type != "vos:LinkNode" :
                checkMD5 = srcMD5
            else:
                ### this is a hack .. we should check the data integraty of links too... just not sure how
                checkMD5 = md5.hexdigest()
        else:
            checkMD5 = self.getNode(dest, force=True).props.get('MD5', 'd41d8cd98f00b204e9800998ecf8427e')

        if sendMD5:
            if checkMD5 != md5.hexdigest():
                logging.error("MD5s don't match ( %s -> %s ) " % (src, dest))
                raise OSError(errno.EIO, "MD5s don't match", src)
            return md5.hexdigest()
        if destSize != srcSize and not srcNode.type == 'vos:LinkNode'  :
            logging.error("sizes don't match ( %s -> %s ) " % (src, dest))
            raise IOError(errno.EIO, "sizes don't match", src)
        return destSize

    def fixURI(self, uri):
        """given a uri check if the authority part is there and if it isn't then add the CADC vospace authority"""
        parts = urlparse(uri)
        #TODO implement support for local files (parts.scheme=None and self.rootNode=None
        if parts.scheme is None:
            uri = self.rootNode + uri
        parts = urlparse(uri)
        if parts.scheme != "vos":
            # Just past this back, I don't know how to fix...
            return uri
        ## Check that path name compiles with the standard

        # Check for 'cutout' syntax values.
        path = re.match("(?P<fname>[^\[]*)(?P<ext>(\[\d*\:?\d*\])?(\[\d*\:?\d*,?\d*\:?\d*\])?)",parts.path)
        filename = os.path.basename(path.group('fname'))
        if not re.match("^[\_\-\(\)\=\+\!\,\;\:\@\&\*\$\.\w\~]*$", filename):
            raise IOError(errno.EINVAL, "Illegal vospace container name", filename)
        path = path.group('fname')
        ## insert the default VOSpace server if none given
        host = parts.netloc
        if not host or host == '':
            host = self.VOSpaceServer
        path = os.path.normpath(path).strip('/')
        return "%s://%s/%s" % (parts.scheme, host, path)

    def getNode(self, uri, limit=0, force=False):
        """connect to VOSpace and download the definition of vospace node

        uri   -- a voSpace node in the format vos:/vospaceName/nodeName
        limit -- load children nodes in batches of limit
        """
        #logging.debug("Limit: %s " % ( str(limit)))
        #logging.debug("Getting node %s" % ( uri))
        uri = self.fixURI(uri)
        if force or uri not in self.nodeCache:
            xml_file = self.open(uri, os.O_RDONLY, limit=limit)
            dom = ET.parse(xml_file)
            node = Node(dom.getroot())
            # IF THE CALLER KNOWS THEY DON'T NEED THE CHILDREN THEY
            # CAN SET LIMIT=0 IN THE CALL Also, if the number of nodes
            # on the firt call was less than 500, we likely got them
            # all during the init
            if limit != 0 and node.isdir() and len(node.getNodeList()) > 500 :
                nextURI = None
                while nextURI != node.getNodeList()[-1].uri:
                    nextURI = node.getNodeList()[-1].uri
                    xml_file = self.open(uri, os.O_RDONLY, nextURI=nextURI, limit=limit)
                    next_page = Node(ET.parse(xml_file).getroot())
                    if len(next_page.getNodeList()) > 0 and nextURI == next_page.getNodeList()[0].uri:
                        next_page.getNodeList().pop(0)
                    node.getNodeList().extend(next_page.getNodeList())
                    logging.debug("Next URI currently %s" % ( nextURI))
                    logging.debug("Last URI currently %s" % ( node.getNodeList()[-1].uri ) )
            self.nodeCache[uri] = node            
            for node in self.nodeCache[uri].getNodeList():
                self.nodeCache[node.uri]=node
        return self.nodeCache[uri]


    def getNodeURL(self, uri, method='GET', view=None, limit=0, nextURI=None, cutout=None):
        """Split apart the node string into parts and return the correct URL for this node"""
        uri = self.fixURI(uri)

        if not self.cadc_short_cut and method == 'GET' and view == 'data':
            return self._get(uri)

        if not self.cadc_short_cut and method in ('PUT'):
            # logging.debug("Using _put")
            return self._put(uri)

        parts = urlparse(uri)
        path = parts.path.strip('/')
        server = Client.VOServers.get(parts.netloc,None)

        if server is None:
            return uri
        logging.debug("Node URI: %s, server: %s, parts: %s " %( uri, server, str(parts)))

        if self.cadc_short_cut and ((method == 'GET' and view in ['data', 'cutout']) or method == "PUT") :
            ## only get here if cadc_short_cut == True
            # find out the URL to the CADC data server
            direction = "pullFromVoSpace" if method == 'GET' else "pushToVoSpace"
            transProtocol = ''
            if self.protocol == 'http':
                if method == 'GET':
                    transProtocol = Client.VO_HTTPGET_PROTOCOL
                else:
                    transProtocol = Client.VO_HTTPPUT_PROTOCOL
            else:
                if method == 'GET':
                    transProtocol = Client.VO_HTTPSGET_PROTOCOL
                else:
                    transProtocol = Client.VO_HTTPSPUT_PROTOCOL
 
            url = "%s://%s%s" % (self.protocol, SERVER, "")
            logging.debug("URL: %s" % (url))

            
            form = urllib.urlencode({'TARGET' : self.fixURI(uri), 
                                     'DIRECTION' : direction, 
                                     'PROTOCOL' : transProtocol})
            url = '%s://%s/%s' % ( self.protocol, SERVER, Client.VOTransfer)
            con = VOFile(url, self.certfile, method="POST", folowRedirect=False)
            httpCon.request("POST", Client.VOTransfer, form, headers)
            try:
                response = httpCon.getresponse()
                if response.status == 303:
                    URL = response.getheader('Location', None)
                else:
                    logging.error("GET/PUT shortcut not working. POST to %s returns: %s" % \
                            (Client.VOTransfer, response.status))
            except Exception as e:
                logging.error(str(e))
            finally: 
                httpCon.close()          
  
            if view == "cutout":
                if cutout is None:
                    raise ValueError("For view=cutout, must specify a cutout "
                                     "value of the form"
                                     "[extension number][x1:x2,y1:y2]")

                ext = "&" if "?" in URL else "?"
                URL += ext + "cutout=" + cutout

            logging.debug("Sending short cuturl: %s" %( URL))
            return URL

        if view == "cutout":
            if cutout is None:
                raise ValueError("For view=cutout, must specify a cutout "
                                "value of the form"
                                "[extension number][x1:x2,y1:y2]")

            urlbase = self._get(uri)
            basepath = urlparse(urlbase).path
            ext = "&" if "?" in basepath else "?"
            return urlbase + ext + "cutout=" + cutout

        ### this is a GET so we might have to stick some data onto the URL...
        fields = {}
        if limit is not None:
            fields['limit'] = limit
        if view is not None:
            fields['view'] = view
        if nextURI is not None:
            fields['uri'] = nextURI
        data = ""
        if len(fields) > 0:
            data = "?" + urllib.urlencode(fields)
        logging.debug("data: %s" % data)
        logging.debug("Fields: %s" % str(fields))
        URL = "%s://%s/vospace/nodes/%s%s" % (self.protocol, server, parts.path.strip('/'), data)
        logging.debug("Node URL %s (%s)" % (URL, method))
        return URL

    def link(self, srcURI, linkURI):
        """Make linkURI point to srcURI"""
        if (self.isdir(linkURI)) :
            linkURI = os.path.join(linkURI, os.path.basename(srcURI))
        linkNode = Node(self.fixURI(linkURI), nodeType="vos:LinkNode")
        ET.SubElement(linkNode.node, "target").text = self.fixURI(srcURI)
        URL = self.getNodeURL(linkURI)
        f = VOFile(URL, self.certfile, method="PUT", size=len(str(linkNode)))
        f.write(str(linkNode))
        return f.close()


    def move(self, srcURI, destURI):
        """Move srcUri to targetUri"""
        logging.debug("Moving %s to %s" % (srcURI, destURI))
        transfer = ET.Element("transfer")
        transfer.attrib['xmlns'] = Node.VOSNS
        transfer.attrib['xmlns:vos'] = Node.VOSNS
        ET.SubElement(transfer, "target").text = self.fixURI(srcURI)
        ET.SubElement(transfer, "direction").text = self.fixURI(destURI)
        ET.SubElement(transfer, "keepBytes").text = "false"

        url = "%s://%s%s" % (self.protocol, SERVER, Client.VOTransfer)
        con = VOFile(url, self.certfile, method="POST" , followRedirect=False)
        con.write(ET.tostring(transfer))
        transURL = con.read()
        if  not self.getTransferError(transURL, srcURI):
            return True
        return  False

    def _get(self, uri):
        return self.transfer(uri, "pullFromVoSpace")

    def _put(self, uri):
        return self.transfer(uri, "pushToVoSpace")

    def transfer(self, uri, direction):
        """Build the transfer XML document"""
        protocol = {"pullFromVoSpace": "%sget" % (self.protocol) ,
                    "pushToVoSpace": "%sput" % (self.protocol) }
        transferXML = ET.Element("transfer")
        transferXML.attrib['xmlns'] = Node.VOSNS
        transferXML.attrib['xmlns:vos'] = Node.VOSNS
        ET.SubElement(transferXML, "target").text = uri
        ET.SubElement(transferXML, "direction").text = direction
        ET.SubElement(transferXML, "view").attrib['uri'] = "%s#%s" % (Node.IVOAURL, "defaultview")
        ET.SubElement(transferXML, "protocol").attrib['uri'] = "%s#%s" % (Node.IVOAURL, protocol[direction])
        url = "%s://%s%s" % (self.protocol, SERVER, Client.VOTransfer)
        con = VOFile(url, self.certfile, method="POST", followRedirect=False)
        con.write(ET.tostring(transferXML))
        transURL = con.read()
        logging.debug("Got back %s from trasnfer " % (con))
        con = VOFile(transURL, self.certfile, method="GET", followRedirect=True)
        F = ET.parse(con)

        P = F.find(Node.PROTOCOL)
        # logging.debug("Transfer protocol: %s" % (str(P)))
        if P is None:
            return self.getTransferError(transURL, uri)
        return P.findtext(Node.ENDPOINT)

    def getTransferError(self, url, uri):
        """Follow a transfer URL to the Error message"""
        errorCodes = { 'NodeNotFound': errno.ENOENT,
                       'PermissionDenied': errno.EACCES,
                       'OperationNotSupported': errno.EOPNOTSUPP,
                       'InternalFault': errno.EFAULT,
                       'ProtocolNotSupported': errno.EPFNOSUPPORT,
                       'ViewNotSupported': errno.ENOSYS,
                       'InvalidArgument': errno.EINVAL,
                       'InvalidURI': errno.EFAULT,
                       'TransferFailed': errno.EIO,
                       'DuplicateNode.': errno.EEXIST,
                       'NodeLocked': errno.EPERM}
        jobURL = str.replace(url, "/results/transferDetails", "")
        try:
            phaseURL = jobURL + "/phase"
            sleepTime = 1
            roller = ( '\\' ,'-','/','|','\\','-','/','|' )
            phase = VOFile(phaseURL, self.certfile, method="GET", followRedirect=False).read() 
            # do not remove the line below. It is used for testing
            logging.info("Job URL: " + jobURL + "/phase")
            while phase in ['PENDING', 'QUEUED', 'EXECUTING', 'UNKNOWN' ]:
                # poll the job. Sleeping time in between polls is doubling each time 
                # until it gets to 32sec
                totalSlept = 0
                if(sleepTime <= 32):
                    sleepTime = 2 * sleepTime
                    slept = 0
                    if logging.getLogger('root').getEffectiveLevel() == logging.INFO : 
                        while slept < sleepTime:
                            sys.stdout.write("\r%s %s" % (phase, roller[totalSlept % len(roller)]))
                            sys.stdout.flush()
                            slept += 1
                            totalSlept += 1
                            time.sleep(1)
                    else:
                        time.sleep(sleepTime)
                phase = VOFile(phaseURL, self.certfile, method="GET", followRedirect=False).read() 
                logging.debug("Async transfer Phase for url %s: %s " % (url,  phase))
            if logging.getLogger('root').getEffectiveLevel() == logging.INFO : 
                sys.stdout.write("Done\n")
        except KeyboardInterrupt:
            # abort the job when receiving a Ctrl-C/Interrupt from the client
            logging.error("Received keyboard interrupt")
            con = VOFile(jobURL + "/phase", self.certfile, method="POST", followRedirect=False)
            con.write("PHASE=ABORT")
            con.read()
            raise KeyboardInterrupt
        status = VOFile(phaseURL, self.certfile, method="GET", followRedirect=False).read()
        logging.debug("Phase:  %s" % (status))
        if status in ['COMPLETED']:
            return False
        if status in ['HELD' , 'SUSPENDED', 'ABORTED']:
            ## requeue the job and continue to monitor for completion.
            raise OSError("UWS status: %s" % (status), errno.EFAULT)
        errorURL = jobURL + "/error"
        con = VOFile(errorURL, self.certfile, method="GET")
        errorMessage = con.read()
        logging.debug("Got transfer error %s on URI %s" % (errorMessage, uri))
        target = re.search("Unsupported link target:(?P<target> .*)$", errorMessage)
        if target is not None:
            return target.group('target').strip()
        raise OSError(errorCodes.get(errorMessage, errno.ENOENT), "%s: %s" %( uri, errorMessage ))


    def open(self, uri, mode=os.O_RDONLY, view=None, head=False, URL=None, limit=None, nextURI=None, size=None, cutout=None):
        """Connect to the uri as a VOFile object"""

        ### sometimes this is called with mode from ['w', 'r']
        ### really that's an error, but I thought I'd just accept those are os.O_RDONLY

        logging.debug("URI: %s" % ( uri))
        logging.debug("URL: %s" %(URL))

        if type(mode) == str:
            mode = os.O_RDONLY

        # the URL of the connection depends if we are 'getting', 'putting' or 'posting'  data
        method = None
        if mode == os.O_RDONLY:
            method = "GET"
        elif mode & (os.O_WRONLY | os.O_CREAT) :
            method = "PUT"
        elif mode & os.O_APPEND :
            method = "POST"
        elif mode & os.O_TRUNC:
            method = "DELETE"
        if head:
            method = "HEAD"
        if not method:
            raise IOError(errno.EOPNOTSUPP, "Invalid access mode", mode)
        if URL is None:
            ### we where given one, see if getNodeURL can figure this out.
            URL = self.getNodeURL(uri, method=method, view=view, limit=limit, nextURI=nextURI, cutout=cutout)
        if URL is None:
            ## Dang... getNodeURL failed... maybe this is a LinkNode?
            ## if this is a LinkNode then maybe there is a Node.TARGET I could try instead...
            node = self.getNode(uri)
            if node.type == "vos:LinkNode":
                logging.debug("appears that %s is a linkNode" % ( node.uri))
                target = node.node.findtext(Node.TARGET)
                #logging.debug(target)
                if target is None:
                    #logging.debug("Why is target None?")
                    ### hmm. well, that shouldn't have happened.
                    return None
                if re.search("^vos\://cadc\.nrc\.ca[!~]vospace", target) is not None:
                    #logging.debug("Opening %s with VOFile" %(target))
                    ### try opening this target directly, cross your fingers.
                    return self.open(target, mode, view, head, URL, limit, nextURI, size, cutout)
                else:
                    ### hmm. just try and open the target, maybe python will understand it.
                    #logging.debug("Opening %s with urllib2" % (target))
                    return urllib2.urlopen(target)
        else:
            return VOFile(URL, self.certfile, method=method, size=size)
        return None


    def addProps(self, node):
        """Given a node structure do a POST of the XML to the VOSpace to update the node properties"""
        #logging.debug("Updating %s" % ( node.name))
        #logging.debug(str(node.props))
        ## Get a copy of what's on the server
        new_props = copy.deepcopy(node.props)
        old_props = self.getNode(node.uri,force=True).props
        for prop in old_props:
            if prop in new_props and old_props[prop] == new_props[prop] and old_props[prop] is not None:
                del(new_props[prop])
        node.node = node.create(node.uri, nodeType=node.type, properties=new_props)
        logging.debug(str(node))
        f = self.open(node.uri, mode=os.O_APPEND, size=len(str(node)))
        f.write(str(node))
        f.close()
        return

    def create(self, node):
        f = self.open(node.uri, mode=os.O_CREAT, size=len(str(node)))
        f.write(str(node))
        return f.close()

    def update(self, node, recursive=False):
        """Updates the node properties on the server. For non-recursive updates, node's
           properties are updated on the server. For recursive updates, node should
           only contain the properties to be changed in the node itself as well as
           all its children. """
        ## Let's do this update using the async tansfer method
        URL = self.getNodeURL(node.uri)
        if recursive:
            propURL = "%s://%s%s" % (self.protocol, SERVER, Client.VOProperties)
            con = VOFile(propURL, self.certfile, method="POST", followRedirect=False)
            con.write(str(node))
            transURL = con.read()
            # logging.debug("Got back %s from $Client.VOProperties " % (con))
            # Start the job
            con = VOFile(transURL + "/phase", self.certfile, method="POST", followRedirect=False)
            con.write("PHASE=RUN")
            con.close()
            self.getTransferError(transURL, node.uri)
        else:
            con = VOFile(URL, self.certfile, method="POST", followRedirect=False)
            con.write(str(node))
            con.read()
        return 0
        #f=self.open(node.uri,mode=os.O_APPEND,size=len(str(node)))
        #f.write(str(node))
        #f.close()

    def mkdir(self, uri):
        node = Node(self.fixURI(uri), nodeType="vos:ContainerNode")
        URL = self.getNodeURL(uri)
        f = VOFile(URL, self.certfile, method="PUT", size=len(str(node)))
        f.write(str(node))
        return f.close()

    def delete(self, uri):
        """Delete the node"""
        # logging.debug("%s" % (uri))
        return self.open(uri, mode=os.O_TRUNC).close()

    def getInfoList(self, uri):
        """Retrieve a list of tupples of (NodeName, Info dict)"""
        infoList = {}
        node = self.getNode(uri, limit=None)
        #logging.debug(str(node))
        while node.type == "vos:LinkNode":
            uri = node.target
            try:
               node = self.getNode(uri, limit=None)
            except Exception as e:
               logging.error(str(e))
               break
        for thisNode in node.getNodeList():
            # logging.debug(str(thisNode.name))
            infoList[thisNode.name] = thisNode.getInfo()
        if node.type in [ "vos:DataNode", "vos:LinkNode" ]:
            infoList[node.name] = node.getInfo()
        return infoList.items()

    def listdir(self, uri, force=False):
        """
        Walk through the directory structure a al os.walk.
        Setting force=True will make sure no caching of results are used.
        """
        #logging.debug("getting a listing of %s " % ( uri))
        names = []
        logging.debug(str(uri))
        node = self.getNode(uri, limit=None, force=force)
        while node.type == "vos:LinkNode":
            uri = node.target
            # logging.debug(uri)
            node = self.getNode(uri, limit=None, force=force)
        for thisNode in node.getNodeList():
            names.append(thisNode.name)
        return names

    def isdir(self, uri):
        """Check to see if this given uri points at a containerNode or is a link to one."""
        try:
            node = self.getNode(uri, limit=0)
            # logging.debug(node.type)
            while node.type == "vos:LinkNode":
                uri = node.target
                # logging.debug(uri)
                if uri[0:4] == "vos:":
                    # logging.debug(uri)
                    node = self.getNode(uri, limit=0)
                else:
                    return False
            if node.type == "vos:ContainerNode":
                return True
        except:
            pass 
        return False

    def isfile(self, uri):
        try:
            return self.status(uri)
        except:
            return False

    def access(self, uri, mode=os.O_RDONLY):
        """Test for existance"""
        try:
            dum = self.getNode(uri)
            return True
        except Exception as e:
            # logging.debug(str(e))
            return False

    def status(self, uri, code=[200, 303, 302]):
        """Check to see if this given uri points at a containerNode.

        This is done by checking the view=data header and seeing if you get an error.
        """
        return self.open(uri, view='data', head=True).close(code=code)

    def getJobStatus(self, url):
        """ Returns the status of a job """
        return VOFile(url, self.certfile, method="GET",
                                    followRedirect=False).read()
