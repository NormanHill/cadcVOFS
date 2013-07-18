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
from settings import CADC_GMS_PREFIX


class Node:
    """A VOSpace node"""

    IVOAURL = "ivo://ivoa.net/vospace/core"
    CADCURL = "ivo://cadc.nrc.ca/vospace/core"

    VOSNS = "http://www.ivoa.net/xml/VOSpace/v2.0"
    XSINS = "http://www.w3.org/2001/XMLSchema-instance"
    TYPE = '{%s}type' % XSINS
    NODES = '{%s}nodes' % VOSNS
    NODE = '{%s}node' % VOSNS
    PROTOCOL = '{%s}protocol' % VOSNS
    PROPERTIES = '{%s}properties' % VOSNS
    PROPERTY = '{%s}property' % VOSNS
    ACCEPTS = '{%s}accepts' % VOSNS
    PROVIDES = '{%s}provides' % VOSNS
    ENDPOINT = '{%s}endpoint' % VOSNS
    TARGET = '{%s}target' % VOSNS


    ### reservered vospace properties, not to be used for extended property setting
    vosProperties = ["description", "type", "encoding", "MD5", "length", "creator", "date",
                     "groupread", "groupwrite", "ispublic", "islocked"]




    def __init__(self, node, nodeType="vos:DataNode", properties={}, xml=None, subnodes=[]):
        """Create a Node object based on the DOM passed to the init method

        if node is a string then create a node named node of nodeType with properties
        """

        if type(node) == unicode or type(node) == str:
            node = self.create(node, nodeType, properties, subnodes=subnodes)

        if node is None:
            raise LookupError("no node found or created?")

        self.node = node
        self.target = None
        self.node.set('xmlns:vos', self.VOSNS)
        self.type = None
        self.props = {}
        self.attr = {}
        self.xattr = {}
        self._nodeList = None
        self.update()

    def __eq__(self, node):
        return self.props == node.props

    def update(self):
        """Update the convience links of this node as we update the xml file"""

        self.type = self.node.get(Node.TYPE)
        if self.type == None:
            #logging.debug("Node type unknown, no node created")
            #logging.debug(ET.dump(self.node))
            return None
        if self.type == "vos:LinkNode":
            self.target = self.node.findtext(Node.TARGET)

        self.uri = self.node.get('uri')
        self.name = os.path.basename(self.uri)
        for propertiesNode in self.node.findall(Node.PROPERTIES):
            self.setProps(propertiesNode)
        self.isPublic = False
        if self.props.get('ispublic', 'false') == 'true':
            self.isPublic = True
        self.isLocked = False
        if self.props.get('islocked', 'false') == 'true':
            self.isLocked = True
        self.groupwrite = self.props.get('groupwrite', '')
        self.groupread = self.props.get('groupread', '')
        self.setattr()
        self.setxattr()

    def setProperty(self, key, value):
        """Given a dictionary of props build a properies subelement"""
        properties = self.node.find(Node.PROPERTIES)
        uri = "%s#%s" % (Node.IVOAURL, key)
        ET.SubElement(properties, Node.PROPERTY,
                      attrib={'uri': uri, 'readOnly': 'false'}).text = value


    def __str__(self):
        class dummy:
            pass
        data = []
        file = dummy()
        file.write = data.append
        ET.ElementTree(self.node).write(file, encoding="UTF-8")
        return "".join(data)

    def setattr(self, attr={}):
        """return a dictionary of attributes associated with the file stored at node

        These attributes are determind from the node on VOSpace.
        """
        ## Get the flags for file mode settings.

        self.attr = {}
        node = self

        ## Only one date provided by VOSpace, so use this as all possible dates.
        sdate = node.props.get('date', None)
        atime = time.time()
        if not sdate:
            mtime = atime
        else:
            ### mktime is expecting a localtime but we're sending a UT date, so some correction will be needed
            mtime = time.mktime(time.strptime(sdate[0:-4], '%Y-%m-%dT%H:%M:%S'))
            mtime = mtime - time.mktime(time.gmtime()) + time.mktime(time.localtime())
        self.attr['st_ctime'] = attr.get('st_ctime', mtime)
        self.attr['st_mtime'] = attr.get('st_mtime', mtime)
        self.attr['st_atime'] = atime

        ## set the MODE by orring together all flags from stat
        st_mode = 0
        self.attr['st_nlink'] = 1

        if node.type == 'vos:ContainerNode':
            st_mode |= stat.S_IFDIR
            self.attr['st_nlink'] = len(node.getNodeList()) + 2
        elif node.type == 'vos:LinkNode':
            st_mode |= stat.S_IFLNK
        else:
            st_mode |= stat.S_IFREG


        ## Set the OWNER permissions
        ## All files are read/write/execute by owner...
        st_mode |= stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR

        ## Set the GROUP permissions
        if node.props.get('groupwrite', "NONE") != "NONE":
            st_mode |= stat.S_IWGRP
        if node.props.get('groupread', "NONE") != "NONE":
            st_mode |= stat.S_IRGRP
            st_mode |= stat.S_IXGRP

        # Set the OTHER permissions
        if node.props.get('ispublic', 'false') == 'true':
            # If you can read the file then you can execute too.
            # Public does NOT mean writeable.  EVER
            st_mode |= stat.S_IROTH | stat.S_IXOTH

        self.attr['st_mode'] = attr.get('st_mode', st_mode)

        # TODO
        # We set the owner and group bits to be those of the currently running process.  
        # This is a hack since we don't have an easy way to figure these out.  

        self.attr['st_uid'] = attr.get('st_uid', os.getuid())
        self.attr['st_gid'] = attr.get('st_uid', os.getgid())
        self.attr['st_size'] = attr.get('st_size', int(node.props.get('length', 0)))
        self.attr['st_blocks'] = self.attr['st_size']/512

    def setxattr(self, attrs={}):
        """Initialize the attributes using the properties sent with the node"""
        for key in self.props:
            if key in Node.vosProperties:
                continue
            self.xattr[key] = self.props[key]
        return

    def chwgrp(self, group):
        """Set the groupwrite value for this node"""
        if (group != None) and (group.count(CADC_GMS_PREFIX) > 3):
            raise AttributeError("Exceeded max of 4 write groups: " + 
                    group.replace(CADC_GMS_PREFIX, ""))
        self.groupwrite = group
        return self.changeProp('groupwrite', group)

    def chrgrp(self, group):
        """Set the groupread value for this node"""
        if (group != None) and (group.count(CADC_GMS_PREFIX) > 3):
            raise AttributeError("Exceeded max of 4 read groups: " + 
                    group.replace(CADC_GMS_PREFIX, ""))
        self.groupread = group
        return self.changeProp('groupread', group)

    def setPublic(self, value):
        #logging.debug("Setting value of ispublic to %s" % (str(value)))
        return self.changeProp('ispublic', value)

    def fix_prop(self,prop):
        """Check if prop is a well formed uri and if not then make into one"""
        (url,tag) = urllib.splittag(prop)
        if tag is None and url in  ['title',
                                    'creator',
                                    'subject',
                                    'description',
                                    'publisher',
                                    'contributer',
                                    'date',
                                    'type',
                                    'format',
                                    'identifier',
                                    'source',
                                    'language',
                                    'relation',
                                    'coverage',
                                    'rights',
                                    'availableSpace',
                                    'groupread',
                                    'groupwrite',
                                    'publicread',
                                    'quota',
                                    'islocked',
                                    'length',
                                    'mtime',
                                    'ctime',
                                    'ispublic']:
            tag = url
            url = Node.IVOAURL
            prop = url+"#"+tag

        parts = urlparse(url)
        if parts.path is None or tag is None:
            raise ValueError("Invalid VOSpace property uri: %s" % ( prop))

        return prop
   
    def setProp(self):
        """Build the XML for a given node"""

    def changeProp(self, key, value):
        """Change the node property 'key' to 'value'.

        Return 1 if changed.

        This function should be split into 'set' and 'delete'
        """
        #logging.debug("Before change node XML\n %s" % ( self))
        uri = self.fix_prop(key)
        changed = 0
        found = False
        properties = self.node.findall(Node.PROPERTIES)
        for props in properties:
            for prop in props.findall(Node.PROPERTY):
                  if uri != prop.attrib.get('uri', None):
                      continue
                  found = True
                  changed = 1
                  if value is None:
                      ## this is actually a delete property
                      prop.attrib['xsi:nil'] = 'true'
                      prop.attrib["xmlns:xsi"] = Node.XSINS
                      prop.text = ""
                      self.props[self.getPropName(uri)] = None
                  else:
                      prop.text = value
        #logging.debug("key %s changed? %s (1 == yes)" % (key, changed))
        if found or value is None:
            return changed
        ### must not have had this kind of property already, so set value
        #logging.debug("Adding a property: %s" %(key))
        propertyNode = ET.SubElement(props, Node.PROPERTY)
        propertyNode.attrib['readOnly'] = "false"
        ### There should be a '#' in there someplace...
        # propertyNode.attrib["uri"] = "%s#%s" % (Node.IVOAURL, key)
        propertyNode.attrib['uri'] = uri
        propertyNode.text = value
        self.props[self.getPropName(uri)] = value
        #logging.debug("After change node XML\n %s" %( self))
        return 1


    def chmod(self, mode):
        """Set the MODE of this Node...

        translates unix style MODE to voSpace and updates the properties...

        This function is quite limited.  We can make a file publicly
        readable and we can set turn off group read/write permissions,
        that's all. """

        changed = 0

        #logging.debug("Changing mode to %d" % ( mode))
        if  mode & (stat.S_IROTH) :
            changed += self.setPublic('true')
        else:
            changed += self.setPublic('false')

        if  mode & (stat.S_IRGRP):

            changed += self.chrgrp(self.groupread)
        else:
            changed += self.chrgrp('')

        if  mode & stat.S_IWGRP :
           changed += self.chwgrp(self.groupwrite)
        else:
           changed += self.chwgrp('')

        #logging.debug("%d -> %s" % ( changed, changed>0))
        return changed > 0


    def create(self, uri, nodeType="vos:DataNode", properties={}, subnodes=[]):
        """Build the XML needed to represent a VOSpace node returns an ElementTree represenation of the XML

        nodeType   -- the VOSpace node type, likely one of vos:DataNode or vos:ContainerNode
        properties -- a dictionary of the node properties, all assumed to be single words from the IVOA list
        """


        ### Build the root node called 'node'
        node = ET.Element("node")
        node.attrib["xmlns"] = Node.VOSNS
        node.attrib["xmlns:vos"] = Node.VOSNS
        node.attrib[Node.TYPE] = nodeType
        node.attrib["uri"] = uri

        ### create a properties section
        if not properties.has_key('type'):
            properties['type'] = mimetypes.guess_type(uri)[0]
            #logging.debug("set type to %s" % (properties['type']))
        propertiesNode = ET.SubElement(node, Node.PROPERTIES)
        for property in properties.keys():
            propertyNode = ET.SubElement(propertiesNode, Node.PROPERTY)
            propertyNode.attrib['readOnly'] = "false"
            ### There should be a '#' in there someplace...
            propertyNode.attrib["uri"] = "%s" % self.fix_prop(property)
            if properties[property] is None:
                ## this is actually a delete property                                                                                                                                                
                propertyNode.attrib['xsi:nil'] = 'true'
                propertyNode.attrib["xmlns:xsi"] = Node.XSINS
                propertyNode.text = ""
            elif len(properties[property]) > 0:
                propertyNode.text = properties[property]
                    

        ## That's it for link nodes...
        if nodeType == "vos:LinkNode":
            return node

        ### create accepts
        accepts = ET.SubElement(node, Node.ACCEPTS)

        ET.SubElement(accepts, "view").attrib['uri'] = "%s#%s" % (Node.IVOAURL, "defaultview")

        ### create provides section
        provides = ET.SubElement(node, Node.PROVIDES)
        ET.SubElement(provides, "view").attrib['uri'] = "%s#%s" % (Node.IVOAURL, 'defaultview')
        ET.SubElement(provides, "view").attrib['uri'] = "%s#%s" % (Node.CADCURL, 'rssview')

        ### Only DataNode can have a dataview...
        if nodeType == "vos:DataNode":
            ET.SubElement(provides, "view").attrib['uri'] = "%s#%s" % (Node.CADCURL, 'dataview')

        ### if this is a container node then we need to add an empy directory contents area...
        if nodeType == "vos:ContainerNode":
            nodeList = ET.SubElement(node, Node.NODES)
            for subnode in subnodes:
                nodeList.append(subnode.node)
        #logging.debug(ET.tostring(node,encoding="UTF-8"))

        return node

    def isdir(self):
        """Check if target is a container Node"""
        #logging.debug(self.type)
        if self.type == "vos:ContainerNode":
            return True
        return False

    def islink(self):
        """Check if target is a link Node"""
        #logging.debug(self.type)
        if self.type == "vos:LinkNode":
            return True
        return False

    def islocked(self):
        """Check if target state is locked for update/delete."""
        return self.props["islocked"] == "true"

    def getInfo(self):
        """Organize some information about a node and return as dictionary"""
        date = time.mktime(time.strptime(self.props['date'][0:-4], '%Y-%m-%dT%H:%M:%S'))
        #if date.tm_year==time.localtime().tm_year:
        #    dateString=time.strftime('%d %b %H:%S',date)
        #else:
        #    dateString=time.strftime('%d %b  %Y',date)
        creator = string.lower(re.search('CN=([^,]*)', self.props.get('creator', 'CN=unknown_000,')).groups()[0].replace(' ', '_'))
        perm = []
        writeGroup = ""
        readGroup = ""
        for i in range(10):
            perm.append('-')
        perm[1] = 'r'
        perm[2] = 'w'
        if self.type == "vos:ContainerNode":
            perm[0] = 'd'
        if self.type == "vos:LinkNode":
            perm[0] = 'l'
        if self.props.get('ispublic', "false") == "true":
            perm[-3] = 'r'
            perm[-2] = '-'
        writeGroup = self.props.get('groupwrite', 'NONE')
        if writeGroup != 'NONE':
            perm[5] = 'w'
        readGroup = self.props.get('groupread', 'NONE')
        if readGroup != 'NONE':
            perm[4] = 'r'
        isLocked = self.props.get('islocked', "false")            
        #logging.debug("%s: %s" %( self.name,self.props))
        return {"permisions": string.join(perm, ''),
                "creator": creator,
                "readGroup": readGroup,
                "writeGroup": writeGroup,
                "isLocked": isLocked,
                "size": float(self.props.get('length', 0)),
                "date": date,
                "target": self.target}

    def getNodeList(self):
        """Get a list of all the nodes held to by a ContainerNode return a list of Node objects"""
        if (self._nodeList is None):
            self._nodeList = []
            for nodesNode in self.node.findall(Node.NODES):
                for nodeNode in nodesNode.findall(Node.NODE):
                    self.addChild(nodeNode)
        return self._nodeList

    def addChild(self, childEt):
        childNode = Node(childEt)
        self._nodeList.append(childNode)
        return(childNode)

    def clearProps(self):
        logging.debug("Clearing Props")
        properties_node_list = self.node.findall(Node.PROPERTIES)
        for properties_node in properties_node_list:
            for property in properties_node.findall(Node.PROPERTY):
                key = self.getPropName(property.get('uri'))
                if key in self.props:
                    del self.props[key]
                properties_node.remove(property)
        logging.debug("Done Clearing Props")
        return 

    def getInfoList(self):
        """Retrieve a list of tupples of (NodeName, Info dict)"""
        infoList = {}
        for node in self.getNodeList():
            infoList[node.name] = node.getInfo()
        if self.type == "vos:DataNode":
            infoList[self.name] = self.getInfo()
        return infoList.items()

    def setProps(self, props):
        """Set the properties of node, given the properties element of that node"""
        for propertyNode in props.findall(Node.PROPERTY):
            self.props[self.getPropName(propertyNode.get('uri'))] = self.getPropValue(propertyNode)
        return


    def getPropName(self, prop):
        """parse the property uri and get the name of the property"""
        (url, propName) = urllib.splittag(prop)
        if url == Node.IVOAURL:
            return propName
        return prop

    def getPropValue(self, prop):
        """Pull out the value part of node"""
        return prop.text

