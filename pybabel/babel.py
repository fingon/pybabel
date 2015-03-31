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
# Last modified: Tue Mar 31 16:20:24 2015 mstenber
# Edit time:     614 min
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

# These are from the official RFC6216 mentioned implementation defaults
HELLO_INTERVAL = 4
IHU_MULTIPLIER = 3 # send IHU every X HELLO_INTERVAL's
UPDATE_INTERVAL = 4 * HELLO_INTERVAL
IHU_HOLD_TIME_MULTIPLIER = 3.5
ROUTE_EXPIRY_TIME_MULTIPLIER = 3.5
SOURCE_GC_TIME = 3 * 60

# Maybe not in RFC6216?
RECENT_HELLO_MULTIPLIER = 4.5 # mentioned in RFC6216?

# Local hacky defaults
URGENT_JITTER = 0.2
HOP_COUNT = 127
MY_METRIC = 256 # what it costs to visit us; no real metric calc here!
SEQNO_RESEND_TIMES = 3
UPDATE_RESEND_TIMES = 2

INF = 0xFFFF

OP_ADD='replace'
OP_DEL='del'

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
        assert not isinstance(tlv, Update) or not tlv.omitted
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
        self.hello_interval = _b2t(tlv.interval)
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
        if not self.last_hello:
            return INF
        intervals_since = (self.get_sys().time() - self.last_hello) / self.hello_interval
        if intervals_since > RECENT_HELLO_MULTIPLIER:
            return INF
        # TBD: real rxcost calc
        return MY_METRIC
    def get_cost(self):
        # 3.4.3
        if self.transmission_cost == INF:
            return INF
        rxcost = self.get_reception_cost()
        if rxcost == INF:
            return INF
        # Appendix A 2.2 alg (suggested by Juliusz)
        cost = int(rxcost * max(self.transmission_cost, 256) / 256)
        return min(INF-1, cost)
    def queue_ihu(self):
        rxcost = self.get_reception_cost()
        if rxcost == INF:
            return
        ihu = IHU(interval=_t2b(HELLO_INTERVAL * IHU_MULTIPLIER),
                  rxcost=rxcost, **ll_to_tlv_args(self.ip))
        self.i.queue_tlv(ihu)
    def process_update_all(self, tlv, rid, nh):
        rid = rid or self.rid # should not really matter; we share code tho so..
        assert tlv.metric == INF
        for p in self.routes.keys():
            self.process_update(None, tlv, rid, p, nh)
    def process_update(self, tlv, rid, p, nh):
        assert len(rid) == RID_LEN
        _debug('%s process_update', self)
        sk = (p, rid)
        rk = p
        metric = tlv.metric
        def is_feasible_update(): # 3.5.1
            if tlv.metric == INF:
                return True
            if sk not in self.i.b.sources:
                _debug('%s .. %s not in sources', self, sk)
                return True
            d = self.i.b.sources[sk]
            if d['seqno'] < tlv.seqno:
                _debug(' .. new seqno')
                return True
            if d['seqno'] == tlv.seqno and tlv.metric < d['metric']:
                _debug(' .. better metric')
                return True
        # 3.5.4
        if rk not in self.routes:
            if not is_feasible_update():
                return
            if tlv.metric == INF:
                return
            _debug(' .. feasible, not in self.routes, non-inf')
        else:
            r = self.routes[rk]
            if not is_feasible_update():
                if rid != r['rid']:
                    metric = INF # treat as retraction
                else:
                    # 3.8.2.2
                    # SHOULD send unicast seqno req whenever it
                    # unfeasible update for a route that is currently
                    # selected is received.
                    d = self.i.b.valid_selected_routes.get(p, {'r':None})
                    _debug('infeasible update %s <> %s', d, r)
                    if d['r'] == r:
                        tlv = SeqnoReq(seqno=r['seqno'] + 1,
                                       hopcount=HOP_COUNT,
                                       rid=r['rid'],
                                       **prefix_to_tlv_args(p))
                        self.queue_tlv(tlv, URGENT_JITTER)
                    return # ignored if same rid but not feasible
            _debug('.. feasible, in self.routes')
            r['timer'].cancel()
        _debug(' .. added to routes')
        dt = _b2t(tlv.interval)
        self.routes[rk] = dict(seqno=tlv.seqno,
                               metric=metric,
                               interval=dt,
                               nh=nh,
                               rid=rid)
        self.expire_route_timer(rk, initial=True)
    def expire_route_timer(self, rk, initial=False):
        if not initial: _debug('%s expire_route_timer %s', self, rk)
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
        _debug('process_tlvs %s - %s', address, tlvs)
        # 4: non-link-local MUST be ignored
        if not address.is_link_local:
            _debug('process_tlvs - non-link-local %s', address)
            return
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
                if af:
                    tlvfull = tlv.omitted and PrefixTLVTuple(ae=tlv.ae, plen=tlv.plen, body=default_prefix.get(af, b'')[:tlv.omitted] + tlv.body) or tlv
                    # MUST ignore invalid AE
                    try:
                        p = tlv_to_prefix(tlvfull)
                    except ValueError:
                        _error('invalid prefix in update request %s (%s)', tlvfull, tlv)
                        continue
                else:
                    p = None
                if tlv.flags & UPDATE_FLAG_SET_DEFAULT_RID:
                    if af:
                        rid = p.network_address.packed[-RID_LEN:]
                        if len(rid) != RID_LEN:
                            _error('broken implicit rid:%s' % tlv)
                            return
                    else:
                        # TBD - reference implementation sends
                        # AE=0, metric=INF - how do you take last 8
                        # bytes for rid out of that?

                        # ignore it for now..
                        rid = None
                if tlv.flags & UPDATE_FLAG_SET_DEFAULT_PREFIX:
                    default_prefix[af] = p.network_address.packed
                if af:
                    nh = default_nh.get(af, address)
                    self.neighbor(address).process_update(tlv, rid, p, nh)
                else:
                    self.neighbor(address).process_update_all(tlv, rid, address)
            elif isinstance(tlv, RouteReq):
                self.b.process_route_req_i(self, tlv)
            elif isinstance(tlv, SeqnoReq):
                self.b.process_seqno_req_n(self.neighbor(address), tlv)
            elif isinstance(tlv, RID):
                rid = tlv.rid
                if len(rid) != RID_LEN:
                    _error('broken rid tlv: %s', tlv)
                    return
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
        # SHOULD be sent less often than Hellos over links with little
        # packet loss; SHOULD be sent to a multicast address
        if self.seqno % IHU_MULTIPLIER == 0:
            for n in self.neighs.values():
                n.queue_ihu()
        self.seqno = (self.seqno + 1) & 0xFFFF
    def send_tlvs(self, tlvs):
        for b in split_tlvs_to_packets(tlvs):
            self.get_sys().send_multicast(self.ifname, b)
    def queue_update_tlv(self, p, d, *a):
        rid = d['r']['rid']
        assert len(rid) == RID_LEN, 'broken d:%s for %s' % (d, p)
        self.queue_tlv(RID(rid=rid))
        r = d.get('r', {})
        u = Update(flags=0, omitted=0, interval=_t2b(UPDATE_INTERVAL),
                   seqno=r.get('seqno', 0), metric=d['metric'],
                   **prefix_to_tlv_args(p))
        self.queue_tlv(u, *a)

class Babel:
    # Every time freshly initialized structures -> can be defined here

    selected_routes = {}
    # [prefix] = {'metric', 'n', 'r' => route struct within n.routes (but may be historic copy too!}

    valid_selected_routes = {}
    # selected_routes with metric < INF

    recently_forwarded_seqnoreq_set = set()
    # set of forwarded requests, cleared every time we do update_timer
    # (this is a SHOULD)

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

        #self.requests = {} # pending request table, per 3.2.6
        # [prefix] = {'rid', 'seqno', 'neigh', 'times', 'timer'}
        # n/a - implemented otherwise

        self.local_routes = set()

        self.update_timer()
    def interface(self, name, ip=None):
        if name not in self.ifs:
            if not ip: ip = self.sys.get_if_ip(name)
            assert ip
            self.ifs[name] = BabelInterface(self, name, ip)
        return self.ifs[name]
    def process_inbound(self, ifname, address, b):
        try:
            p = Packet.decode(b)
        except:
            _debug('process_inbound - decode failure')
            return
        self.interface(ifname).process_tlvs(address, p.tlvs)
    def route_selection(self):
        _debug('%s Babel.route_selection' % self)
        # 3.6
        sr = {}
        for i in self.ifs.values():
            for n in i.neighs.values():
                nc = n.get_cost()
                for p, r in n.routes.items():
                    # TBD - _I_ do not really want to select IPv4 routes
                    # _at all_ but for 'complete' experience someone might
                    if isinstance(p.network_address,
                                  ipaddress.IPv4Address):
                        continue
                    if nc == INF or r['metric'] == INF:
                        m = INF
                    else:
                        m = min(INF-1, nc + r['metric'])
                    if p in sr and sr[p]['metric'] < m:
                        continue
                    # Do not add new route as blackhole route
                    if p not in self.selected_routes and m == INF:
                        continue
                    sr[p] = dict(metric=m, n=n, r=r)
        _debug(' remote routes: %s', sr)
        # Finally, override selected routes with local ones
        for p in self.local_routes:
            r = dict(rid=self.rid, seqno=self.seqno, metric=MY_METRIC)
            # TBD local metric?
            sr[p] = dict(metric=MY_METRIC, n=None, r=r)
        def _to_route(d):
            ifname = d['n'].i.ifname
            nh = d.get('r', {}).get('nh', d['n'].ip)
            return dict(ifname=ifname, nh=nh)
        sr0 = self.selected_routes
        s1 = set([k for k in sr0.keys() if sr0[k]['n']])
        s2 = set([k for k in sr.keys() if sr[k]['n']])
        # New routes
        for p in s2.difference(s1):
            self.sys.set_route(op=OP_ADD, prefix=p, **_to_route(sr[p]))
        # Updated routes
        for p in s1.intersection(s2):
            # 3.7.2 (triggered updates)
            # MUST send update in timely manner if rid changes
            if sr[p]['r']['rid'] != sr0[p]['r']['rid']:
                self.queue_update(p, sr[p], URGENT_JITTER)
                # SHOULD make sure it is received by everyone (2/5 sends)
                self.queue_update_timer(p, sr[p], initial=True)
            # If state is unchanged, ignore
            if (sr0[p]['metric'] == INF) == (sr[p]['metric'] == INF):
                continue
            if sr[p]['metric'] == INF:
                # Fresh blackhole
                self.sys.set_route(op=OP_DEL, prefix=p, **_to_route(sr[p]))
                self.sys.set_route(blackhole=True, op=OP_ADD, prefix=p)

                # 3.7.2 SHOULD send if route redacted
                self.queue_update(p, sr[p], URGENT_JITTER)

                # 3.8.2.1 MUST send seqno request (no feasible routes)
                self.queue_seqno_req_timer(p, sr0[p]['r'], initial=True)
            else:
                # No longer blackhole
                self.sys.set_route(blackhole=True, op=OP_DEL, prefix=p)
                self.sys.set_route(op=OP_ADD, prefix=p, **_to_route(sr[p]))
        # Old, hold time expired routes
        for p in s1.difference(s2):
            self.sys.set_route(blackhole=True, op=OP_DEL, prefix=p)
        self.selected_routes = sr
        vsr = dict([(k, v) for (k, v) in sr.items() if sr[k]['metric'] < INF])
        self.valid_selected_routes = vsr
    def queue_update_timer(self, p, d, times=UPDATE_RESEND_TIMES, initial=False):
        if not initial:
            if p not in self.selected_routes or \
                   self.selected_routes[p]['r']['rid'] != d['r']['rid']:
                return
        self.queue_update(p, d)
        if times > 1:
            self.sys.call_later(URGENT_JITTER * 2,
                                self.queue_update_timer, p, d, times-1)
    def queue_seqno_req_timer(self, p, r, times=SEQNO_RESEND_TIMES, initial=False):
        # Ensure route is in blackhole mode
        if not initial and p in self.valid_selected_routes: return
        tlv = SeqnoReq(seqno=r['seqno'] + 1,
                       hopcount=HOP_COUNT,
                       rid=r['rid'],
                       **prefix_to_tlv_args(p))
        # SHOULD be sent in timely manner
        self.queue_tlv(tlv, URGENT_JITTER)
        if times > 1:
            # resending is a SHOULD
            self.sys.call_later(URGENT_JITTER * 2,
                                self.queue_seqno_req_timer, p, r, times - 1)
    def maintain_feasibility(self, p, d):
        # 3.7.3 maintain feasibility distance
        if d['metric'] == INF:
            #_debug('%s maintain_feasibility: %s inf', self, p)
            return
        r = d['r']
        sk = (p, r['rid'])
        rd = dict(seqno=r['seqno'], metric=d['metric'])
        if sk not in self.sources:
            sd = rd
            self.sources[sk] = rd
            _debug('%s maintain_feasibility: %s new source %s', self, sk, sd)
        else:
            sd = self.sources[sk]
            if r['seqno'] > sd['seqno']:
                sd.update(rd)
                _debug('%s maintain_feasibility: %s new seqno %s', self, sk, sd)
            elif r['seqno'] == sd['seqno'] and d['metric'] < sd['metric']:
                sd.update(rd)
                _debug('%s maintain_feasibility: %s better metric %s', self, sk, sd)
            sd['timer'].cancel()
        sd['timer'] = self.sys.call_later(SOURCE_GC_TIME,
                                          self.source_gc_timer, sk)
    def source_gc_timer(self, sk):
        _debug('source_gc_timer %s', sk)
        del self.sources[sk]
    def update_timer(self):
        # Simplification from the official data model; we have only
        # system-wide update timer.

        # 3.7.1
        for p, d in sorted(self.valid_selected_routes.items(),
                                key=lambda x:(x[1]['r']['rid'], x[0])):
            self.queue_update(p, d)
        self.sys.call_later(UPDATE_INTERVAL, self.update_timer)
        self.recently_forwarded_seqnoreq_set = set()
    def queue_tlv(self, tlv, *a):
        for i in self.ifs.values():
            i.queue_tlv(tlv, *a)
    def queue_update(self, p, d, *a):
        self.maintain_feasibility(p, d)
        for i in self.ifs.values():
            i.queue_update_tlv(p, d, *a)
    def process_route_req_i(self, i, tlv):
        # 3.8.1.1
        if tlv.ae == 0:
            # SHOULD send full routing table dump
            for p, d in self.valid_selected_routes.items():
                i.queue_update_tlv(p, d)
            return
        # MUST send an update to individual req.
        try:
            p = tlv_to_prefix(tlv)
        except ValueError:
            _error('invalid prefix in process_route_req_i: %s', tlv)
            return
        d = self.valid_selected_routes.get(p)
        d = d or {'metric': INF, 'r': {'rid': self.rid}}
        i.queue_update_tlv(p, d)
    def process_seqno_req_n(self, n, tlv):
        i = n.i
        # 3.8.1.2
        try:
            p = tlv_to_prefix(tlv)
        except ValueError:
            _error('invalid prefix in process_seqno_req_n: %s', tlv)
            return
        d = self.valid_selected_routes.get(p)
        if d is None: return # not present, ignored

        rid, seqno = d['r']['rid'], d['r']['seqno']

        # First step: rid different or seqno valid -> send
        if tlv.rid != rid or tlv.seqno <= seqno:
            n.i.queue_update_tlv(p, d)
            return

        if tlv.rid == rid and tlv.seqno > seqno:
            if tlv.rid == self.rid:
                self.seqno += 1
                d['r']['seqno'] = self.seqno
                n.i.queue_update_tlv(p, d)
                return

        # not us, seqno > what we know; forward

        # first off, hopcount - if about to expire, skip
        if tlv.hopcount < 2:
            return

        # SHOULD keep track of recently forwarded requests
        rk = (tlv.rid, tlv.seqno)
        if rk in self.recently_forwarded_seqnoreq_set:
            _debug('queue_seqno_req_to_best for %s: recently sent', rk)
            return
        self.recently_forwarded_seqnoreq_set.add(rk)

        # look for best next hop
        best = None
        for i2 in self.ifs.values():
            for n2 in i2.neighs.values():
                r2 = n2.routes.get(p)
                if not r2: continue
                if r2['metric'] == INF: continue
                if n2.get_cost() == INF: continue
                if r2['rid'] != tlv.rid: continue
                if n2 == n: continue
                if not best or best[0] > n2.get_cost():
                    best = [n2.get_cost(), n2]
        # MUST be forwarded to single neighbor only
        if not best:
            _debug('queue_seqno_req_to_best for %s: no target found', rk)
            return
        tlv2 = SeqnoReq(seqno=tlv.seqno,
                        hopcount=tlv.hopcount-1,
                        rid=tlv.rid,
                        **prefix_to_tlv_args(p))
        _debug('queue_seqno_req_to_best to %s', best)
        best[1].queue_tlv(tlv2, URGENT_JITTER)
