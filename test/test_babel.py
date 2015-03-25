#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: test_babel.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Wed Mar 25 10:46:15 2015 mstenber
# Last modified: Wed Mar 25 12:31:23 2015 mstenber
# Edit time:     45 min
#
"""

Unit tests for the core babel module.

This more or less replicates net_sim in the hnetd repository, but in Python.

I.e. it simulates time, topology, and allows for arbitrary set of
topology connections to be made (and unmade) over time.

"""

from pybabel.babel import *
import collections
import random

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug

DELIVERY_DELAY_MAX=0.2

class FakeTimeout:
    done = False
    def __init__(self, fs, t, cb, a):
        assert cb is not None
        self.fs = fs
        self.t = t
        self.cb = cb
        self.a = a
        _debug('%s FakeTimeout %s', self, cb)
    def cancel(self):
        assert not self.done
        assert self in self.fs.timeouts
        _debug('%s FakeTimeout.cancel', self)
        self.fs.timeouts.remove(self)
        self.done = True
    def run(self):
        assert not self.done
        assert self in self.fs.timeouts
        _debug('%s FakeTimeout.run %s', self, self.cb)
        self.cb(*self.a)
        self.fs.timeouts.remove(self)
        self.done = True

class FakeSystem:
    t = 123456789
    sid = 0
    def __init__(self):
        self.timeouts = []

        self.connections = collections.defaultdict(set)
        # (s, ifname) => [(s2, ifname2) list]
    def set_connected(self, k1, k2, enabled=True):
        l = self.connections[k1]
        if k2 in l == enabled:
            return
        if not enabled:
            l.remove(k2)
        else:
            l.add(k2)
    def poll(self):
        while True:
            l = [x for x in self.timeouts if x.t <= self.t]
            if not l:
                return
            l[0].run()
            # Just run them one by one as I CBA to track the cancel
            # dependencies :p
    def next(self):
        if not self.timeouts: return
        return min([x.t for x in self.timeouts])
    def run_until(self, cb, *a, max_iterations=100):
        iteration = 0
        while not cb(*a):
            nt = self.next()
            assert nt
            if nt > self.t:
                self.t = nt
            self.poll()
            iteration += 1
            assert iteration < max_iterations

class FakeSystemInterface(SystemInterface):
    def __init__(self, fs):
        self.fs = fs
        self.iid = 0
        fs.sid += 1
        self.sid = fs.sid
        self.ips = {}
    def time(self):
        return self.fs.t
    def random(self):
        return random.random()
    def call_later(self, dt, cb, *a):
        o = FakeTimeout(self.fs, dt + self.fs.t, cb, a)
        self.fs.timeouts.append(o)
        return o
    def get_rid(self):
        return bytes([0] * 7 + [self.sid])
    def get_if_ip(self, ifname):
        self.iid += 1
        a = ipaddress.ip_address('fe80::')
        b = a.packed[:-2] + bytes([self.sid, self.iid])
        ip = ipaddress.ip_address(b)
        self.ips[ifname] = ip
        return ip
    def send_unicast(self, ifname, ip, b):
        for k in self.fs.connections[self,ifname]:
            (s2, ifname2) = k
            if s2.ips[ifname2] != ip:
                continue
            d = random.random() * DELIVERY_DELAY_MAX
            self.call_later(d, s2.b.process_inbound,
                            ifname2, self.ips[ifname], b)
    def send_multicast(self, ifname, b):
        for k in self.fs.connections[self,ifname]:
            (s2, ifname2) = k
            d = random.random() * DELIVERY_DELAY_MAX
            self.call_later(d, s2.b.process_inbound,
                            ifname2, self.ips[ifname], b)


def test_babel():
    fs = FakeSystem()
    def _add_babel():
        fsi = FakeSystemInterface(fs)
        b = Babel(fsi)
        fsi.b = b
        return b
    b1 = _add_babel()
    b2 = _add_babel()
    b1.local_routes.add(ipaddress.ip_network('2001:db8::/32'))
    b1.interface('i1')
    b2.interface('i2')
    fs.set_connected((b1.sys, 'i1'), (b2.sys, 'i2'))
    fs.set_connected((b2.sys, 'i2'), (b1.sys, 'i1'))
    _debug('looping')
    def _converged(*bl):
        # All local routes must be published
        for b in bl:
            if len(b.selected_routes) < len(b.local_routes):
                _debug('_converged .. not. missing local routes at %s.', b)
                return False
        # Have to have same set of selected routes
        for i in range(1, len(bl)):
            k1 = bl[0].selected_routes.keys()
            k2 = bl[i].selected_routes.keys()
            if k1 != k2:
                _debug('_converged .. not: route key delta %s<>%s' % (k1, k2))
                return False
        return True
    fs.run_until(_converged, b1, b2)
    print(fs.t)
    raise
