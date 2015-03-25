#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: setup.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Wed Mar 25 05:21:26 2015 mstenber
# Last modified: Wed Mar 25 05:22:25 2015 mstenber
# Edit time:     0 min
#
"""

Minimalist setup.py

"""

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

setup(name='pybabel',
      version='0.0.1', # XXXX
      author = 'Markus Stenberg',
      author_email = 'fingon+pybabel@iki.fi',
      packages = ['pybabel'],
      install_requires=[]
      )

