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
# Last modified: Wed Mar 25 08:11:13 2015 mstenber
# Edit time:     151 min
#
"""

The core protocol is here. It depends on 'sys' system interface for
actual heavy lifting (e.g. no sockets here, for unit testability).

"""

from babel.codec import *

# Source, Route, Pending Requests are simply dicts within Babel class.

HELLO_INTERVAL = 4
#IHU_INTERVAL = 3 * HELLO_INTERVAL # n/a here
UPDATE_INTERVAL = 4 * HELLO_INTERVAL
IHU_HOLD_TIME_MULTIPLIER = 3.5
ROUTE_EXPIRY_TIME_MULTIPLIER = 3.5
SOURCE_GC_TIME = 3 * 60
URGENT_JITTER = 0.2

RECENT_HELLO_TIME = 60 # TBD - not clear in RFC!

INF = 0xFFFF

class TLVQueuer:
    t = None
    q = None
    timeout = None
    def queue_tlv(self, j, tlv):
        if self.q is None: self.q = []
        sys = self.get_sys()
        now = sys.time()
        dt = random.random() * j
        t = now + dt
        self.q.append(tlv)
        if self.t is None or self.t > t:
            self.t = t
        else:
            return # old queued callback is fine
        if self.timeout:
            self.timeout.cancel()
        self.timeout = sys.call_later(dt, self.timer_callback)
    def timer_callback(self):
        self.send_queue()
        del self.q
        del self.t
        del self.timeout
    def send_queue(self):
        raise NotImplementedError # child responsibility
    def get_sys(self):
        raise NotImplementedError

class BabelNeighbor(TLVQueuer):
    " A neighbor on BabelInterface "
    transmission_cost = INF
    last_hello = 0 # = hello timer
    ihu_timer = None
    def __init__(self, i, ip):
        self.i = i
        self.ip = ip
        self.routes = {} #3.2.5
        # [prefix] = {'seqno', 'metric', 'nh', ['selected',] 'timer', +'rid'}

        #self.history = []
        #self.expected_seqno = 0

    def get_sys(self):
        return self.i.get_sys()
    def send_queue(self):
        self.get_sys().send_unicast(self.i.ifname, self.ip,
                                    Packet(tlvs=self.q).encode())
    def process_hello(self, tlv):
        self.last_hello = self.get_sys().time()
        self.i.b.route_selection()
    def process_ihu(self, tlv):
        if self.ihu_timer:
            self.ihu_timer.cancel()
        self.update_transmission_cost(tlv.rxcost)
        dt = _b2t(tlv.interval) * IHU_HOLD_TIME_MULTIPLIER
        self.ihu_timer = self.get_sys().call_later(dt, self.ihu_expired)
    def ihu_expired(self):
        self.update_transmission_cost(INF)
    def update_transmission_cost(self, v):
        if self.transmission_cost == v:
            return
        self.transmission_cost = v
        self.i.b.route_selection()
    def get_reception_cost(self):
        if (self.get_sys().time() - last_hello) > RECENT_HELLO_TIME:
            return INF
        # TBD: real rxcost calc
        return 1
    def get_cost(self):
        rxcost = self.get_reception_cost()
        if rxcost == INF:
            return INF
        if self.transmission_cost == INF:
            return INF
        return self.transmission_cost + rxcost
    def queue_ihu(self):
        rxcost = self.get_reception_cost()
        if rxcost == INF:
            return
        ihu = IHU(interval=_t2b(HELLO_INTERVAL),
                  rxcost=rxcost, **_ll2tlv(self.ip))
        self.queue_tlv(HELLO_INTERVAL/2, ihu)
    def process_update(self, tlv, rid, prefix):
        sk = (prefix, rid)
        rk = prefix
        metric = tlv.metric
        def is_feasible_update(): # 3.5.1
            if tlv.metric == INF:
                return True
            if k not in self.sources:
                return True
            d = self.i.b.sources[sk]
            if d['seqno'] < tlv.seqno:
                return True
            if d['seqno'] == tlv.seqno and tlv.metric < d['metric']:
                return True
        # 3.5.4
        if rk not in self.routes:
            if not is_feasible_update(): return
            if tlv.metric == INF: return
        else:
            d = self.routes[rk]
            if not is_feasible_update():
                if rid != d['rid']:
                    metric = INF # treat as retraction
                else:
                    return # ignored if same rid but not feasible
            d['timer'].cancel()
        dt = _b2t(tlv.interval)
        self.routes[rk] = dict(seqno=tlv.seqno,
                               metric=metric,
                               interval=dt,
                               nh=nh,
                               rid=rid)
        self.expire_route_timer(rk, initial=True)
    def expire_route_timer(self, rk, initial=False):
        assert rk in self.routes
        d = self.routes[rk]
        if not initial:
            if d['metric'] == INF:
                del self.routes[rk]
            d['metric'] = INF
        if rk in self.routes:
            d['timer'] = self.sys.call_later(ROUTE_EXPIRY_TIME_MULTIPLIER * d['interval'],
                                             self.expire_route_timer,
                                             rk)
        self.i.b.route_selection()

def _ll2tlv(ip):
    s = ip.exploded.replace(':', '')
    assert len(s) == 32
    s = s[16:] # skip first 8 bytes
    b = binascii.unhexlify(s)
    return {'ae': 3, 'body': b}


def _b2t(v):
    return v / 100.0

def _t2b(v):
    return int(v * 100)

class BabelInterface(TLVQueuer):
    def __init__(self, b, ifname):
        self.b = b
        self.ifname = ifname

        self.neighs = {}

        # per-if hello seqno
        self.seqno = 0

        # TBD update timer

        # Start by sending hello immediately
        self.hello_timer()
    def get_sys(self):
        return self.b.sys
    def hello_timer(self):
        self.queue_hello()
        self.hello_timer = self.b.sys.call_later(HELLO_INTERVAL,
                                                 self.hello_timer)
    def neighbor(self, ip):
        if name not in self.neighs:
            self.neighs[ip] = BabelNeighbor(self, ip)
        return self.neighs[ip]
    def process_tlvs(self, address, tlvs):
        for tlv in tlvs:
            if isinstance(tlv, AckReq):
                self.neighbor(address).queue_tlv(_b2t(tlv.interval),
                                                 Ack(nonce=tlv.nonce))
            elif isinstance(tlv, Hello):
                self.neighbor(address).process_hello(tlv)
            elif isinstance(tlv, IHU):
                self.neighbor(address).process_ihu(tlv)
            elif isinstance(tlv, Update):
                self.neighbor(address).process_update(tlv, rid, prefix)
    def queue_hello(self):
        self.queue_tlv(HELLO_INTERVAL/2,
                       Hello(seqno=self.seqno,
                             interval=_t2b(self.b.hello_interval)))
        # Queue also IHUs for every neighbor
        for ip, n in self.neighs():
            n.queue_ihu()
        self.seqno = (self.seqno + 1) & 0xFFFF
    def send_queue(self):
        self.get_sys().send_multicast(self.i.ifname,
                                      Packet(tlvs=self.q).encode())


class Babel:
    def __init__(self, sys):
        self.sys = sys
        self.ifs = {}

        # SHOULD be mod-EUI64; TBD
        self.rid = ''.join(chr(random.randint(0,255)) for x in range(8))

        self.seqno = 0

        self.sources = {}
        # source table, per 3.2.4
        # [(prefix, rid)] = {'seqno', 'metric', 'timer'}

        self.requests = {} # pending request table, per 3.2.6
        # [prefix] = {'rid', 'seqno', 'neigh', 'times', 'timer'}

        self.selected_routes = {}
        # [prefix] = {'metric', 'n', 'r'}
    def interface(self, name):
        if name not in self.ifs:
            self.ifs[name] = BabelInterface(self, name)
        return self.ifs[name]

    def process_inbound(self, ifname, address, p):
        self.interface(ifname).process_tlvs(address, Packet.decode(p))

    def route_selection(self):
        # 3.6
        sr = {}
        for i in self.ifs.values():
            for n in i.neighs.values():
                nc = n.get_cost()
                if nc == INF:
                    continue
                for p, r in n.routes.items():
                    if r['metric'] == INF:
                        continue
                    m = nc + r['metric']
                    if prefix in sr and sr[prefix]['metric'] < m:
                        continue
                    sr[prefix] = dict(metric=m, n=n, r=r)
        # 3.7.2
        for prefix, d in sr.items():
            if not prefix in self.selected_routes:
                continue
            d2 = self.selected_routes[prefix]
            # MUST send update in timely manner if rid changes
            if d2['r']['rid'] != d['r']['rid']:
                self.queue_update(URGENT_JITTER, prefix, d)
            # SHOULD send if route redacted
            if d2['r']['metric'] < INF and d['r']['metric'] == INF:
                self.queue_update(URGENT_JITTER, prefix, d)
    def maintain_feasibility(self, d):
        # 3.7.3 maintain feasibility distance
        if d['metric'] == INF:
            return
        sk = (prefix, d['rid'])
        if sk not in self.sources:
            sd = {'seqno': d['seqno'],
                  'metric': d['metric']}
            self.sources[sk] = sd
        else:
            sd = self.sources[sk]
            if d['seqno'] > sd['seqno']:
                sd.update(dict(seqno=d['seqno'],
                               metric=d['metric']))
                sd['timer'].cancel()
            elif d['seqno'] == sd['seqno'] and d['metric'] < sd['metric']:
                sd['metric'] = d['metric']
                sd['timer'].cancel()
            else:
                return
        sd['timer'] = self.sys.call_later(SOURCE_GC_TIME, self.source_gc_timer, sk)
    def source_gc_timer(self, sk):
        del self.sources[sk]
    def queue_update(self, j, prefix, d):
        self.maintain_feasibility(d)
        xxx
