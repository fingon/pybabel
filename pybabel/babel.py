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
# Last modified: Thu Mar 26 05:38:26 2015 mstenber
# Edit time:     355 min
#
"""

The core protocol is here. It depends on 'sys' system interface for
actual heavy lifting (e.g. no sockets here, for unit testability).

"""

from pybabel.codec import *

import collections

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug
_error = _logger.error

# Source, Route, Pending Requests are simply dicts within Babel class.

HELLO_INTERVAL = 4
#IHU_INTERVAL = 3 * HELLO_INTERVAL # n/a here
UPDATE_INTERVAL = 4 * HELLO_INTERVAL
IHU_HOLD_TIME_MULTIPLIER = 3.5
ROUTE_EXPIRY_TIME_MULTIPLIER = 3.5
SOURCE_GC_TIME = 3 * 60
URGENT_JITTER = 0.2
HOP_COUNT = 16

MTU_ISH = 1400 # random MTU we use for splitting TLVs when we send stuff

RECENT_HELLO_TIME = 60 # TBD - not clear in RFC!

INF = 0xFFFF

class SystemInterface:
    def time(self):
        raise NotImplementedError
    def random(self):
        raise NotImplementedError
    def call_later(self, fn, cb, *a):
        raise NotImplementedError
    def get_rid(self):
        raise NotImplementedError
    def get_if_ip(self, ifname):
        raise NotImplementedError
    def send_unicast(self, ifname, ip, b):
        raise NotImplementedError
    def send_multicast(self, ifname, b):
        raise NotImplementedError
    def set_route(self, add, p, ifname, nhip):
        raise NotImplementedError

class TLVQueuer:
    tlv_t = None
    tlv_q = None
    tlv_timeout = None
    def queue_tlv(self, tlv, j=HELLO_INTERVAL / 2):
        _debug('%s queue_tlv %s %s', self, tlv, j)
        if self.tlv_q is None: self.tlv_q = []
        sys = self.get_sys()
        now = sys.time()
        dt = sys.random() * j
        t = now + dt
        self.tlv_q.append(tlv)
        if self.tlv_t and self.tlv_t <= t:
            # old queued callback is fine
            return
        if self.tlv_timeout is not None:
            self.tlv_timeout.cancel()
        self.tlv_t = t
        self.tlv_timeout = sys.call_later(dt, self.tlv_send_timer)
        assert self.tlv_timeout is not None
    def tlv_send_timer(self):
        assert self.tlv_q
        self.send_tlvs(self.tlv_q)
        del self.tlv_q
        del self.tlv_t
        del self.tlv_timeout
    def send_tlvs(self):
        raise NotImplementedError # child responsibility
    def get_sys(self):
        raise NotImplementedError

def sort_and_eliminate_tlvs_with_same_rid(tlvs):
    # Note: this is not really generic; instead, we _know_ we have RID
    # before every TLV that needs one..
    rid = None
    by_rid = collections.defaultdict(list)
    for tlv in tlvs:
        if isinstance(tlv, RID):
            rid = tlv.rid
        elif rid:
            by_rid[rid].append(tlv)
            rid = None
        else:
            yield tlv
    for rid, l in by_rid.items():
        yield RID(rid=rid)
        for e in l:
            yield e

def split_tlvs_to_tlv_lists(tlvs):
    c = 4 # packet header
    l = []
    # TBD: could do clever things to Update TLVs here but out of scope
    # (address compression)
    for tlv in tlvs:
        tl = len(tlv.encode())
        if tl + c > MTU_ISH:
            yield l
            c = 4
            l = []
        c += tl
        l.append(tlv)
    if l:
        yield l

def split_tlvs_to_packets(tlvs):
    tlvs = sort_and_eliminate_tlvs_with_same_rid(tlvs)
    # SHOULD maximize size, but MUST NOT send larger than ..
    for tlvs in split_tlvs_to_tlv_lists(tlvs):
        yield Packet(tlvs=tlvs).encode()

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
    def send_tlvs(self, tlvs):
        for b in split_tlvs_to_packets(tlvs):
            self.get_sys().send_unicast(self.i.ifname, self.ip, b)
    def process_hello(self, tlv):
        _debug('%s process_hello', self)
        self.last_hello = self.get_sys().time()
        self.i.b.route_selection()
    def process_ihu(self, tlv):
        _debug('%s process_ihu %s', self, tlv)
        if tlv.ae != 0:
            # If it has address set, and it is not us, ignore
            # (~implicit based on reading of 4.4.6)
            try:
                ip = tlv_to_ip_or_ll(tlv)
            except:
                _debug(' not parseable')
                # 4.4.6 - invalid IHU AE => ignore
                return
            if ip != self.i.ip:
                _debug(' wrong target %s != %s', ip, self.i.ip)
                return
        if self.ihu_timer:
            self.ihu_timer.cancel()
        self.update_transmission_cost(tlv.rxcost)
        dt = _b2t(tlv.interval) * IHU_HOLD_TIME_MULTIPLIER
        self.ihu_timer = self.get_sys().call_later(dt, self.ihu_expired_timer)
    def ihu_expired_timer(self):
        self.update_transmission_cost(INF)
    def update_transmission_cost(self, v):
        if self.transmission_cost == v:
            return
        _debug('update_transmission_cost => %d', v)
        self.transmission_cost = v
        self.i.b.route_selection()
    def get_reception_cost(self):
        # Strictly speaking, this should be in get_cost, but this works too
        if (self.get_sys().time() - self.last_hello) > RECENT_HELLO_TIME:
            return INF
        # TBD: real rxcost calc
        return 1
    def get_cost(self):
        # 3.4.3
        if self.transmission_cost == INF:
            return INF
        rxcost = self.get_reception_cost()
        if rxcost == INF:
            return INF
        return self.transmission_cost + rxcost
    def queue_ihu(self):
        rxcost = self.get_reception_cost()
        if rxcost == INF:
            return
        ihu = IHU(interval=_t2b(HELLO_INTERVAL),
                  rxcost=rxcost, **ll_to_tlv_args(self.ip))
        self.i.queue_tlv(ihu)
    def process_update_all(self, tlv, rid, nh):
        assert tlv.metric == INF
        for prefix in self.routes.keys():
            self.process_update(tlv, rid, prefix, nh)
    def process_update(self, tlv, rid, prefix, nh):
        _debug('%s process_update', self)
        sk = (prefix, rid)
        rk = prefix
        metric = tlv.metric
        def is_feasible_update(): # 3.5.1
            if tlv.metric == INF:
                return True
            if sk not in self.i.b.sources:
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
        _debug(' .. added to routes')
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
            sys = self.get_sys()
            dt = ROUTE_EXPIRY_TIME_MULTIPLIER * d['interval']
            d['timer'] = sys.call_later(dt, self.expire_route_timer, rk)
        self.i.b.route_selection()


def _b2t(v):
    return v / 100.0

def _t2b(v):
    return int(v * 100)

PrefixTLVTuple = collections.namedtuple('PrefixTLVTuple', 'ae body plen')

class BabelInterface(TLVQueuer):
    def __init__(self, b, ifname, ip):
        self.b = b
        self.ifname = ifname
        self.ip = ip
        self.neighs = {}

        # per-if hello seqno
        self.seqno = 0

        # Queue hello immediately
        self.hello_timer()

        # And wildcard update request
        self.queue_tlv(RouteReq(ae=0, plen=0))
    def get_sys(self):
        return self.b.sys
    def hello_timer(self):
        self.queue_hello()
        self.b.sys.call_later(HELLO_INTERVAL, self.hello_timer)
    def neighbor(self, ip):
        if ip not in self.neighs:
            self.neighs[ip] = BabelNeighbor(self, ip)
        return self.neighs[ip]
    def process_tlvs(self, address, tlvs):
        rid = None
        default_prefix = {}
        default_nh = {2: address}
        for tlv in tlvs:
            if isinstance(tlv, AckReq):
                self.neighbor(address).queue_tlv(Ack(nonce=tlv.nonce),
                                                 _b2t(tlv.interval))
            elif isinstance(tlv, Hello):
                self.neighbor(address).process_hello(tlv)
            elif isinstance(tlv, IHU):
                self.neighbor(address).process_ihu(tlv)
            elif isinstance(tlv, Update):
                af = tlv.ae == 3 and 2 or tlv.ae
                if tlv.flags & 0x40:
                    rid = tlv.body[-8:]
                if af:
                    tlvfull = tlv.omitted and PrefixTLVTuple(ae=tlv.ae, plen=tlv.plen, body=default_prefix.get(af, b'')[:tlv.omitted] + tlv.body) or tlv
                    # MUST ignore invalid AE
                    try:
                        prefix = tlv_to_prefix(tlvfull)
                    except ValueError:
                        _error('invalid prefix in update request %s (%s)', tlvfull, tlv)
                        continue
                    if tlv.flags & 0x80:
                        default_prefix[af] = prefix.network_address.packed
                    nh = default_nh.get(af, address)
                    self.neighbor(address).process_update(tlv, rid, prefix, nh)
                else:
                    self.neighbor(address).process_update_all(tlv, rid, address)
            elif isinstance(tlv, RouteReq):
                self.b.process_route_req_i(self, tlv)
            elif isinstance(tlv, SeqnoReq):
                self.b.process_seqno_req_n(self.neighbor(address), tlv)
            elif isinstance(tlv, RID):
                rid = tlv.rid
            elif isinstance(tlv, NH):
                af = tlv.ae == 3 and 2 or tlv.ae
                # Unknown ones MUST be silently ignored
                try:
                    default_nh[af] = tlv_to_ip_or_ll(tlv)
                except:
                    pass
    def queue_hello(self):
        self.queue_tlv(Hello(seqno=self.seqno,
                             interval=_t2b(HELLO_INTERVAL)))
        # Queue also IHUs for every neighbor
        for n in self.neighs.values():
            n.queue_ihu()
        self.seqno = (self.seqno + 1) & 0xFFFF
    def send_tlvs(self, tlvs):
        for b in split_tlvs_to_packets(tlvs):
            self.get_sys().send_multicast(self.ifname, b)

class Babel:
    def __init__(self, sys):
        assert isinstance(sys, SystemInterface)
        self.sys = sys
        self.ifs = {}

        # SHOULD be mod-EUI64; hopefully system provides that
        self.rid = sys.get_rid()

        self.seqno = 0

        self.sources = {}
        # source table, per 3.2.4
        # [(prefix, rid)] = {'seqno', 'metric', 'timer'}

        self.requests = {} # pending request table, per 3.2.6
        # [prefix] = {'rid', 'seqno', 'neigh', 'times', 'timer'}

        self.selected_routes = {}
        # [prefix] = {'metric', 'n', 'r' => route struct within n.routes (but may be historic copy too!}
        self.local_routes = set()

        self.update_timer()
    def interface(self, name, ip=None):
        if name not in self.ifs:
            if not ip: ip = self.sys.get_if_ip(name)
            assert ip
            self.ifs[name] = BabelInterface(self, name, ip)
        return self.ifs[name]
    def process_inbound(self, ifname, address, b):
        # 4: non-link-local MUST be ignored
        if not address.is_link_local:
            _debug('process_inbound - non-link-local %s', address)
            return
        try:
            p = Packet.decode(b)
        except:
            _debug('process_inbound - decode failure')
            return
        _debug('process_inbound %s - %s', address, p.tlvs)
        self.interface(ifname).process_tlvs(address, p.tlvs)
    def route_selection(self):
        _debug('%s Babel.route_selection' % self)
        # 3.6
        sr = {}
        for i in self.ifs.values():
            for n in i.neighs.values():
                nc = n.get_cost()
                if nc == INF:
                    _debug(' %s unreachable (%d/%d), skip', n, n.get_reception_cost(), n.transmission_cost)
                    continue
                for prefix, r in n.routes.items():
                    if r['metric'] == INF:
                        _debug(' route to %s unreachable via %s', prefix, n)
                        continue
                    # TBD - _I_ do not really want to select IPv4 routes
                    # _at all_ but for 'complete' experience someone might
                    if isinstance(r['nh'], ipaddress.IPv4Address):
                        continue
                    m = nc + r['metric']
                    if prefix in sr and sr[prefix]['metric'] < m:
                        _debug(' have better route to %s than %s', prefix, n)
                        continue
                    _debug(' using %s via %s', prefix, n)
                    sr[prefix] = dict(metric=m, n=n, r=r)
        _debug(' remote routes: %s', sr)
        # Finally, override selected routes with local ones
        for prefix in self.local_routes:
            r = dict(rid=self.rid, seqno=self.seqno, metric=0)
            sr[prefix] = dict(metric=0, n=None, r=r)
        # 3.7.2 (triggered updates)
        for prefix, d in sr.items():
            if not prefix in self.selected_routes:
                continue
            d2 = self.selected_routes[prefix]
            # MUST send update in timely manner if rid changes
            if d2['r']['rid'] != d['r']['rid']:
                self.queue_update(prefix, d, URGENT_JITTER)
        for prefix, d in self.selected_routes.items():
            if prefix in sr:
                continue
            # SHOULD send if route redacted
            self.queue_update(prefix, d, URGENT_JITTER)
            # 3.8.2.1 MUST send seqno request (no feasible routes)
            tlv = SeqnoReq(seqno=d['r']['seqno'] + 1,
                           hopcount=HOP_COUNT,
                           rid=d['r']['rid'],
                           **prefix_to_tlv_args(prefix))
            # SHOULD be sent in timely manner
            self.queue_tlv(tlv, URGENT_JITTER)
        def _sr_to_set(sr):
            return set([(p, d['n'].i.ifname, d.get('r', {}).get('nh', d['n'].ip))
                        for p, d in sr.items() if d['n']])
        s1 = _sr_to_set(self.selected_routes)
        s2 = _sr_to_set(sr)
        self.selected_routes = sr
        for e in s1.difference(s2):
            self.sys.set_route(False, *e)
        for e in s2.difference(s1):
            self.sys.set_route(True, *e)
    def maintain_feasibility(self, prefix, d):
        # 3.7.3 maintain feasibility distance
        if d['metric'] == INF:
            return
        r = d['r']
        sk = (prefix, r['rid'])
        if sk not in self.sources:
            sd = {'seqno': r['seqno'],
                  'metric': d['metric']}
            self.sources[sk] = sd
        else:
            sd = self.sources[sk]
            if r['seqno'] > sd['seqno']:
                sd.update(dict(seqno=r['seqno'],
                               metric=d['metric']))
                sd['timer'].cancel()
            elif r['seqno'] == sd['seqno'] and d['metric'] < sd['metric']:
                sd['metric'] = d['metric']
                sd['timer'].cancel()
            else:
                return
        sd['timer'] = self.sys.call_later(SOURCE_GC_TIME,
                                          self.source_gc_timer, sk)
    def source_gc_timer(self, sk):
        del self.sources[sk]
    def update_timer(self):
        # Simplification from the official data model; we have only
        # system-wide update timer.

        # 3.7.1
        for prefix, d in self.selected_routes.items():
            self.queue_update(prefix, d)
        self.sys.call_later(UPDATE_INTERVAL, self.update_timer)
    def queue_tlv(self, tlv, *a):
        for i in self.ifs.values():
            i.queue_tlv(tlv, *a)
    def queue_update(self, prefix, d, *a):
        self.maintain_feasibility(prefix, d)
        self.queue_update_tlv(prefix, d, *a)
    def queue_update_tlv(self, prefix, d, *a):
        if 'rid' in d.get('r', {}):
            self.queue_tlv(RID(rid=d['r']['rid']))
        self.queue_tlv(self.to_update_tlv(prefix, d), *a)

    def to_update_tlv(self, prefix, d):
        flags = 0
        omitted = 0
        interval = UPDATE_INTERVAL
        r = d.get('r', {})
        u = Update(flags=flags, omitted=omitted, interval=_t2b(interval),
                   seqno=r.get('seqno', 0), metric=d['metric'],
                   **prefix_to_tlv_args(prefix))
        return u
    def process_route_req_i(self, i, tlv):
        # 3.8.1.1
        if tlv.ae == 0:
            # SHOULD send full routing table dump
            for prefix, d in self.selected_routes.items():
                self.queue_update_tlv(prefix, d)
            return
        # MUST send an update to individual req.
        try:
            prefix = tlv_to_prefix(tlv)
        except ValueError:
            _error('invalid prefix in process_route_req_i: %s', tlv)
            return
        d = self.selected_routes.get(prefix)
        d = d or {'metric': INF}
        self.queue_update_tlv(prefix, d)
    def process_seqno_req_n(self, n, tlv):
        i = n.i
        # 3.8.1.2
        try:
            prefix = tlv_to_prefix(tlv)
        except ValueError:
            _error('invalid prefix in process_seqno_req_n: %s', tlv)
            return
        d = self.selected_routes.get(prefix)
        if d is None: return # not present, ignored
        if d['metric'] == INF: return # infinite metric
        r = d['r']
        if tlv.rid != d['rid'] or tlv.seqno <= r['seqno']:
            # MUST send update if prefix varies or
            # ' no smaller'
            self.queue_update_tlv(prefix, d)
            return
        if tlv.rid == d['rid'] and tlv.seqno > r['seqno']:
            if tlv.rid == self.rid:
                self.seqno += 1
                r['seqno'] += self.seqno
                self.queue_update_tlv(prefix, d)
                return
            if tlv.hopcount >= 2:
                best = None
                for i2 in self.ifs.values():
                    for n2 in i2.neighs.values():
                        r2 = n2.routes.get(prefix)
                        if not r2: continue
                        if r2['metric'] == INF: continue
                        if n2.get_cost() == INF: continue
                        if n2 == n: continue
                        if not best or best[0] > n2.get_cost():
                            best = [n2.get_cost(), n2]
                # MUST be forwarded to single neighbor only
                if best:
                    tlv2 = SeqnoReq(seqno=tlv.seqno,
                                    hopcount=tlv.hopcount-1,
                                    rid=tlv.rid,
                                    **prefix_to_tlv_args(prefix))
                    best[1].queue_tlv(tlv2, URGENT_JITTER)
