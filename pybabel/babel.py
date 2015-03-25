#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: babel.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Wed Mar 25 03:48:40 2015 mstenber
# Last modified: Wed Mar 25 05:19:59 2015 mstenber
# Edit time:     58 min
#
"""

The core protocol is here. It depends on 'sys' system interface for
actual heavy lifting (e.g. no sockets here, for unit testability).

"""

# Source, Route, Pending Requests are simply dicts within Babel class.

class BabelNeighbor:
    " A neighbor on BabelInterface "
    def __init__(self, i, ip):
        self.i = i
        self.ip = ip

        #self.history = []
        #self.transmission_cost = 0
        #self.expected_seqno = 0

        # TBD hello timer, ihu timer

class BabelInterface:
    def __init__(self, b, ifname):
        self.b = b
        self.ifname = ifname

        self.neighs = {}

        # per-if hello seqno
        self.seqno = 0

        # TBD update timer

        # Start by sending hello immediately
        self.hello_callback()

    def hello_callback(self):

        self.hello_timer = self.b.sys.call_later(self.b.hello_interval,
                                                 self.hello_callback)

    def neighbor(self, ip):
        if name not in self.neighs:
            self.neighs[ip] = BabelNeighbor(self, ip)
        return self.neighs[ip]

class Babel:
    hello_interval = 3
    def __init__(self, sys):
        self.sys = sys
        self.ifs = {}

        # SHOULD be mod-EUI64; TBD
        self.rid = ''.join(chr(random.randint(0,255)) for x in range(8))
        # babel
        self.seqno = 0

        self.sources = {}
        # source table, per 3.2.4
        # [(prefix, rid)] = {'seqno', 'metric', 'timer'}

        self.routes = {} # route table, per 3.2.5
        # [(prefix, neigh)] = {'seqno', 'metric', 'nh', 'selected', 'timer'}

        self.requests = {} # pending request table, per 3.2.6
        # [prefix] = {'rid', 'seqno', 'neigh', 'times', 'timer'}

    def interface(self, name):
        if name not in self.ifs:
            self.ifs[name] = BabelInterface(self, name)
        return self.ifs[name]


