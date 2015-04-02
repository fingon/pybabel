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
# Last modified: Thu Apr  2 10:45:45 2015 mstenber
# Edit time:     209 min
#
"""

Unit tests for the core babel module.

This more or less replicates net_sim in the hnetd repository, but in Python.

I.e. it simulates time, topology, and allows for arbitrary set of
topology connections to be made (and unmade) over time.

"""

from pybabel.babel import *
import pybabel.codec
import collections
import random

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug

DELIVERY_DELAY_MAX=0.2

orig_decode_error = pybabel.codec._decode_error

class FakeTimeout:
    done = False
    def __init__(self, fs, t, cb, a):
        assert cb is not None
        self.fs = fs
        self.t = t
        self.cb = cb
        self.a = a
        _debug('%s FakeTimeout %s', self, cb)
        def _f(desc, x):
            assert False, 'decode error:%s in %s' % (desc, x)
        pybabel.codec._decode_error = _f
    def __del__(self):
        pybabel.codec._decode_error = orig_decode_error
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
            k1 = bl[0].valid_selected_routes.keys()
            k2 = bl[i].valid_selected_routes.keys()
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
    add = ipaddress.ip_address('fe80::1')
    ifo.process_tlvs(add, [rr])
    assert ifo.tlv_q[-1].metric != INF

    rr = RouteReq(**prefix_to_tlv_args(prefix2))
    ifo.process_tlvs(add, [rr])
    assert ifo.tlv_q[-1].metric == INF

    rr = RouteReq(**prefix_to_tlv_args(prefix))
    ifo.process_tlvs(add, [rr])
    assert ifo.tlv_q[-1].metric != INF

    assert fs.routes_are_sane()

    # Make sure that we handle ae=0 Update correctly. i.e. state disappears.
    ifo2 = b2.interface('i2')
    b1ip = ifo.ip
    assert ifo2.neighbor(b1ip).routes[prefix]['metric'] < INF
    ifo2.process_tlvs(b1ip,
                     [Update(flags=0, omitted=0, interval=1, seqno=124,
                             metric=INF, ae=0)])
    assert ifo2.neighbor(b1ip).routes[prefix]['metric'] == INF


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

    fs.run_until(lambda :not b2.sources, max_iterations=1000)

def _test_babel_tree(n, brf, ifc):
    fs = FakeSystem()
    for i in range(n):
        b = fs.add_babel()
        j = i // brf
        if i != j:
            ifn = 'down%d' % (i % brf % ifc)
            b2 = fs.babels[j]
            fs.set_connected((b2.sys, ifn), (b.sys, 'up'), bidir=True)
            b.interface('up')
            b2.interface(ifn)
        # Add one local route to each node
        prefix = ipaddress.ip_network('2001:db8:%d::/48' % i)
        b.local_routes.add(prefix)
    fs.run_until(fs.converged, max_iterations=1000)
    assert fs.routes_are_sane()
    return fs

def test_babel_tree_small():
    _test_babel_tree(7, 2, 1)

def _test_babel_tree_small_2():
    _test_babel_tree(7, 2, 2)

def _test_babel_tree_big():
    _test_babel_tree(13, 5, 3)


fakea = ipaddress.ip_address('fe80::1')
fakea2 = ipaddress.ip_address('fe80::2')
uiname = 'up'
diname = 'down0'

def test_rfc6126_must():
    fs = _test_babel_tree(3, 2, 1)
    (b0, b1, b2) = fs.babels
    fakep = ipaddress.ip_network('dead:beef::/32')

    # 3.1: Ack TLV MUST be sent <= deadline
    # 3.3: MUST be able to respond to AckReq (.. with Ack)
    # 3.3: Ack MUST be sent to a unicast destination
    bui = b0.interface(uiname)
    bdi = b0.interface(diname)
    bdi.process_tlvs(fakea, [AckReq(interval=1, nonce=123)])
    bdin = bdi.neighbor(fakea)
    assert bdin.tlv_q and bdin.tlv_t <= fs.t + 0.02
    bdin.tlv_send_timer()

    # 3.4.3: MUST be strictly positive cost, and INF
    # if no recent hellos / txcost INF
    # TBD (how to test?)

    # 3.5.2: c inf => M(c, m) = inf, M(c, m) > m
    # TBD (how to test?)

    # 3.5.5: MUST NOT be forwarded in blackhole state
    # (done in test_babel; blackhole routes are created)

    # 3.6: INF metric MUST NOT be selected; unfeasible route MUST NOT
    # be selected
    # (implied strongly; valid_selected_routes)


    # 3.1: 3.7.2 updates MUST be sent in timely manner
    # 3.7.2: MUST send a triggered update if rid changes for dest
    if bdi.tlv_q: bdi.tlv_send_timer()
    rprefix = list(b2.local_routes)[0]
    fakerid = b'12345678'
    bdi.process_tlvs(fakea, [Hello(seqno=123, interval=1),
                             IHU(rxcost=1, interval=1, **ll_to_tlv_args(bdi.ip)),
                             RID(rid=fakerid),
                             Update(flags=0, omitted=0, interval=1, seqno=123,
                                    metric=1, **prefix_to_tlv_args(rprefix))])
    assert bdi.tlv_q and bdi.tlv_t <= fs.t + URGENT_JITTER
    # 3.7.2: SHOULD make sure it is received by everyone (2/5 sends)
    # (= >1 resend; one already in queue, another in timer)
    assert len([tlv for tlv in bdi.tlv_q if isinstance(tlv, Update)])
    bdi.tlv_send_timer()

    assert [t for t in fs.timeouts if t.cb == b0.queue_update_timer]

    # 3.8.1.1: MUST send an update if route exists
    bdi.process_tlvs(fakea, [RouteReq(**prefix_to_tlv_args(rprefix))])
    assert not bdin.tlv_q and bdi.tlv_q
    assert len([tlv for tlv in bdi.tlv_q if isinstance(tlv, Update)])
    bdi.tlv_send_timer()

    # 3.8.1.1: MUST send an update (retraction) if route does not exist
    bdi.process_tlvs(fakea, [RouteReq(**prefix_to_tlv_args(fakep))])
    assert not bdin.tlv_q and bdi.tlv_q
    assert len([tlv for tlv in bdi.tlv_q if isinstance(tlv, Update)])
    bdi.tlv_send_timer()

    # 3.8.1.2 MUST send an update if seqno <= expected
    bdi.process_tlvs(fakea, [SeqnoReq(hopcount=2, rid=fakerid, seqno=121,
                                      **prefix_to_tlv_args(rprefix))])
    assert not bdin.tlv_q and bdi.tlv_q
    assert len([tlv for tlv in bdi.tlv_q if isinstance(tlv, Update)])
    bdi.tlv_send_timer()

    # 3.8.1.2 MUST NOT increment seqno by more than 1
    osn = b0.seqno
    b0p = list(b0.local_routes)[0]
    bdi.process_tlvs(fakea, [SeqnoReq(hopcount=2, rid=b0.rid, seqno=osn+5,
                                      **prefix_to_tlv_args(b0p))])
    assert not bdin.tlv_q and bdi.tlv_q
    assert len([tlv for tlv in bdi.tlv_q if isinstance(tlv, Update)])
    assert b0.seqno == osn + 1
    bdi.tlv_send_timer()

    # 3.8.1.2 SHOULD forward if hopcount>1
    for n in bdi.neighs.values():
        if n.tlv_q: n.tlv_send_timer()
    bdi.process_tlvs(fakea2, [SeqnoReq(hopcount=5, rid=fakerid, seqno=124,
                                       **prefix_to_tlv_args(rprefix))])
    assert not bdi.tlv_q
    # There has to be bdin but no other neighbor..
    queued_neighs = [n for n in bdi.neighs.values() if n.tlv_q]
    # MUST NOT be forwarded to a multicast address (duh)
    # MUST be sent just to single neighbor
    assert len(queued_neighs) == 1
    n = queued_neighs[0]
    assert bdin == n
    l = [tlv for tlv in n.tlv_q if isinstance(tlv, SeqnoReq)]
    assert l and l[0].hopcount == 4
    n.tlv_send_timer()
    # SHOULD maintain list of recently forwarded,
    # SHOULD compare against recently forwarded
    bdi.process_tlvs(fakea, [SeqnoReq(hopcount=5, rid=fakerid, seqno=124,
                                      **prefix_to_tlv_args(rprefix))])
    for n in bdi.neighs.values():
        assert not n.tlv_q
    # or hopcount=1
    bdi.process_tlvs(fakea, [SeqnoReq(hopcount=1, rid=fakerid, seqno=125,
                                      **prefix_to_tlv_args(rprefix))])
    for n in bdi.neighs.values():
        assert not n.tlv_q

    # 3.8.2.1: MUST send SeqnoReq if all feasible routes gone
    # (seqno = known seqno + 1)
    bdi.neighbor(fakea).expire_route_timer(rprefix)
    l = [tlv for tlv in bdi.tlv_q if isinstance(tlv, SeqnoReq)]
    assert len(l) == 0

    # still one route left - the original towards b2
    bdi.neighbor(b1.interface(uiname).ip).expire_route_timer(rprefix)
    l = [tlv for tlv in bdi.tlv_q if isinstance(tlv, SeqnoReq)]
    assert len(l) == 1, bdi.tlv_q
    assert l[0].seqno == b2.seqno + 1

    # SHOULD be sent on all interfaces
    l = [tlv for tlv in bui.tlv_q if isinstance(tlv, SeqnoReq)]
    assert len(l) >= 1, bui.tlv_q
    assert l[-1].seqno == b2.seqno + 1


    bdi.tlv_send_timer()

    # 4: MUST be ignored if SA != linklocal
    globa = ipaddress.ip_address('2001:db8::1')
    bdi.process_tlvs(globa, [AckReq(interval=1, nonce=123)])
    assert globa not in bdi.neighs

    # 4: MUST NOT be sent as jumbograms (...)
    # TBD (n/a)

    # 4: MUST NOT send packets larger than the attached interface's
    # MTU
    # TBD (done but..)

    # 4: MUST be able to receive <= if-MTU packets
    # TBD (n/a)

    # 4: MUST buffer every TLV
    # 4: MUST NOT be >= half hello interval
    # TBD (done but..)

    # encode/decode MUSTs covered in test_codec

def test_rfc6126_should():
    fs = _test_babel_tree(3, 2, 1)
    (b0, b1, b2) = fs.babels
    bui = b0.interface(uiname)
    bdi = b0.interface(diname)

    _debug('test_rfc6126_should setup done')

    # TBD - something for the rainy day.. :-p

    # 3.1: outgoing TLVs SHOULD be sent with a delay
    # 3.1: 3.8.2 updates SHOULD be sent in timely manner
    # TBD (done but..)

    # 3.2.1: node SHOULD NOT increment seqno spontaneously (check)

    # 3.4.1: hello interval SHOULD NOT be increased except before
    # sending a Hello packet.
    # 3.4.1: if changing interval, node SHOULD send an unscheduled Hello
    # TBD (n/a; we do not change the interval)

    # 3.5.2: M isotonic (m <= m' ==> M(c, m) <= M(c, m')

    # 3.7.2: SHOULD NOT send triggered update for other reasons
    # TBD (n/a, proving negative is hard)

    # 3.7.4: SHOULD use split horizon
    # SHOULD NOT be applied to an interface unless known to be
    # symmetric+transitive
    # TBD _NOT implemented_

    # 3.8.1.1: wildcard -> SHOULD send full dump
    # TBD (done but ..)

    # 3.8.2.1: SHOULD send seqno-req > 1 times
    # TBD (done but ..)

    # 3.8.2.2: on non-feasible update, SHOULD send unicast seqno req

    # Feasibility updates is done only periodically when sending updates;
    # force it first
    b0.update_timer()

    bdin = bdi.neighbor(fakea)

    b1ip = b1.interface(uiname).ip
    assert not bdi.neighbor(b1ip).tlv_q
    rprefix = list(b2.local_routes)[0]
    seqno = bdi.neighbor(b1ip).routes[rprefix]['seqno']
    bdi.process_tlvs(b1ip,
                     [RID(rid=b2.rid),
                      Update(flags=0, omitted=0, interval=1, seqno=seqno,
                             metric=12345, **prefix_to_tlv_args(rprefix))])
    assert bdi.neighbor(b1ip).tlv_q

    # 3.8.2.3: SHOULD send unicast route req 'shortly' before expiration

def test_update_flag_40():
    fs = FakeSystem()
    b = fs.add_babel()
    i = b.interface('x')
    fakep = ipaddress.ip_network('dead:beef:1:2:3:4:5:6/128')
    i.process_tlvs(fakea,
                   [Update(flags=0x40, omitted=0, interval=1, seqno=0,
                           metric=1, **prefix_to_tlv_args(fakep))])
    fakerid = bytes([0, 3, 0, 4, 0, 5, 0, 6])
    assert i.neighbor(fakea).routes[fakep]['rid'] == fakerid


def test_github_issue_4():
    fs = FakeSystem()
    b = fs.add_babel()
    i = b.interface('x')
    fakep = ipaddress.ip_network('dead:beef:1:2:3:4:5:6/128')
    fake_ihu_interval = 100

    tlvs = [Hello(seqno=123, interval=fake_ihu_interval),
            IHU(rxcost=1, interval=fake_ihu_interval, **ll_to_tlv_args(i.ip))]
    i.process_tlvs(fakea, tlvs)

    # The issue was that _after_ the IHU had timed out (no message
    # within interval), receiving another IHU caused a boom. So wait a bit.
    et = fs.t + fake_ihu_interval * IHU_HOLD_TIME_MULTIPLIER * 3 / 2
    fs.run_until(lambda :fs.t >= et, max_iterations=1000)

    i.process_tlvs(fakea, tlvs)
