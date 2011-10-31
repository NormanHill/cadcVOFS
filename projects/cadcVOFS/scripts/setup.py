#!/usr/bin/env python

from distutils.core import setup

setup(name="vofs",
      version="1.1",
      url="http://www.cadc.hia.nrc.gc.ca/vosui/#jkavelaars/",
      description="CADC VOSpace Filesystem",
      author="JJ Kavelaars",
      author_email="jj.kavelaars@nrc.gc.ca",
      py_modules=['fuse','vos'],
      scripts=['getCert','vcp','vrm','vls','vmkdir','mountvofs','vrmdir']
)
