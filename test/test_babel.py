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
# Last modified: Fri Mar 27 07:59:07 2015 mstenber
# Edit time:     104 min
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
        self.babels = []
        self.ip2b = {}
        self.connections = collections.defaultdict(set)
        # (s, ifname) => [(s2, ifname2) list]
    def add_babel(self):
        fsi = FakeSystemInterface(self)
        b = Babel(fsi)
        self.babels.append(b)
        fsi.b = b
        return b
    def set_connected(self, k1, k2, enabled=True, bidir=False):
        l = self.connections[k1]
        if k2 in l == enabled:
            return
        if not enabled:
            l.remove(k2)
        else:
            l.add(k2)
        if bidir:
            self.set_connected(k2, k1, enabled)
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
                _debug('time now %s', nt)
            self.poll()
            iteration += 1
            assert iteration < max_iterations
    def routes_are_sane(self):
        # Make sure that for any selected routes, they wind up at the
        # source with local_routes set for the prefix
        for b in self.babels:
            for p, d in b.selected_routes.items():
                if not self.route_is_sane(b, p):
                    return False
        return True
    def route_is_sane(self, b, p, hopcount=64):
        d = b.selected_routes[p]
        n = d.get('n')
        if not n:
            assert p in b.local_routes
            return True
        if not hopcount:
            return
        return self.route_is_sane(self.ip2b[n.ip], p, hopcount-1)
    def converged(self):
        bl = self.babels
        # All local routes must be published
        for i, b in enumerate(bl):
            if len(b.selected_routes) < len(b.local_routes):
                _debug('_converged .. not. missing local routes at #%d %s.', i, b)
                return False
        # Have to have same set of selected routes
        for i in range(1, len(bl)):
            k1 = bl[0].get_valid_selected_routes().keys()
            k2 = bl[i].get_valid_selected_routes().keys()
            if k1 != k2:
                _debug('_converged .. not: route key delta %s<>%s' % (k1, k2))
                return False
        return True



class FakeSystemInterface(SystemInterface):
    def __init__(self, fs):
        self.fs = fs
        self.iid = 0
        fs.sid += 1
        self.sid = fs.sid
        self.ips = {}
        self.route_changes = []
    def time(self):
        return self.fs.t
    def random(self):
        return random.random()
    def call_later(self, dt, cb, *a):
        o = FakeTimeout(self.fs, dt + self.fs.t, cb, a)
        self.fs.timeouts.append(o)
        return o
    def get_rid(self):
        return bytes([0] * (RID_LEN-1) + [self.sid])
    def get_if_ip(self, ifname):
        self.iid += 1
        a = ipaddress.ip_address('fe80::')
        b = a.packed[:-2] + bytes([self.sid, self.iid])
        ip = ipaddress.ip_address(b)
        self.ips[ifname] = ip
        self.fs.ip2b[ip] = self.b
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
    def set_route(self, **kw):
        _debug('%s set_route %s', self, kw)
        self.route_changes.append(kw)

def test_babel():
    fs = FakeSystem()
    b1 = fs.add_babel()
    b2 = fs.add_babel()
    prefix = ipaddress.ip_network('2001:db8::/32')
    prefix2 = ipaddress.ip_network('fe80::/64')
    b1.local_routes.add(prefix)
    b1.interface('i1')
    b2.interface('i2')
    fs.set_connected((b1.sys, 'i1'), (b2.sys, 'i2'), bidir=True)
    _debug('looping')
    fs.run_until(fs.converged)
    assert b1.selected_routes[prefix]['n'] is None
    n2 = b2.selected_routes[prefix]['n']
    assert n2 is not None
    assert n2.ip == b1.interface('i1').ip

    # Ok, test some particular claims in the RFC.
    ifo = b1.interface('i1')
    ifo.tlv_q = []
    rr = RouteReq(ae=0)
    add = ipaddress.ip_address('2001:db8::1')
    ifo.process_tlvs(add, [rr])
    assert ifo.tlv_q[-1].metric != INF

    rr = RouteReq(**prefix_to_tlv_args(prefix2))
    ifo.process_tlvs(add, [rr])
    assert ifo.tlv_q[-1].metric == INF

    rr = RouteReq(**prefix_to_tlv_args(prefix))
    ifo.process_tlvs(add, [rr])
    assert ifo.tlv_q[-1].metric != INF

    assert fs.routes_are_sane()

def test_babel_flap():
    fs = FakeSystem()
    b1 = fs.add_babel()
    b2 = fs.add_babel()
    prefix = ipaddress.ip_network('2001:db8::/32')
    prefix2 = ipaddress.ip_network('fe80::/64')
    addr = ipaddress.ip_address('fe80::101')
    b1.local_routes.add(prefix)
    b1.interface('i1')
    b2.interface('i2')
    fs.set_connected((b1.sys, 'i1'), (b2.sys, 'i2'), bidir=True)
    _debug('looping')
    fs.run_until(fs.converged)
    assert fs.routes_are_sane()

    assert len(b1.sys.route_changes) == 0
    assert len(b2.sys.route_changes) == 1
    assert b2.sys.route_changes == [dict(op=OP_ADD, prefix=prefix, ifname='i2', nh=addr)]
    b2.sys.route_changes = []

    fs.set_connected((b1.sys, 'i1'), (b2.sys, 'i2'), False)
    fs.run_until(lambda :not fs.converged())

    assert len(b1.sys.route_changes) == 0
    assert len(b2.sys.route_changes) == 2
    assert b2.sys.route_changes == [dict(op=OP_DEL, prefix=prefix, ifname='i2', nh=addr),
                                    dict(op=OP_ADD, blackhole=True, prefix=prefix)]
    b2.sys.route_changes = []

    fs.run_until(lambda :len(b2.sys.route_changes), max_iterations=1000)
    assert b2.sys.route_changes == [dict(op=OP_DEL, blackhole=True, prefix=prefix)]

def _test_babel_tree(n, brf, ifc):
    fs = FakeSystem()
    for i in range(n):
        b = fs.add_babel()
        j = i // brf
        if i == j:
            # root-ish
            continue
        ifn = 'down%d' % (i % brf % ifc)
        b2 = fs.babels[j]
        fs.set_connected((b2.sys, ifn), (b.sys, 'up'), bidir=True)
        b.interface('up')
        b2.interface(ifn)
        # Add one local route to each node
        prefix = ipaddress.ip_network('2001:db8:%d::/48' % i)
        b.local_routes.add(prefix)
    fs.run_until(fs.converged, max_iterations=10000)
    assert fs.routes_are_sane()

def test_babel_tree_small():
    _test_babel_tree(7, 2, 1)

def _test_babel_tree_small_2():
    _test_babel_tree(7, 2, 2)

def _test_babel_tree_big():
    _test_babel_tree(13, 5, 3)

