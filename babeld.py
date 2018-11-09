#!/usr/bin/env python3.4
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: babeld.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Wed Mar 25 21:53:19 2015 mstenber
# Last modified: Fri Nov  9 13:06:51 2018 mstenber
# Edit time:     180 min
#
"""

Leveraging the pybabel module, minimalist routing daemon.

"""

import ipaddress
import logging
import os
import random
import re
import select
import socket
import struct
import time

from pybabel.babel import RID_LEN, Babel, SystemInterface

_logger = logging.getLogger(__name__)
_debug = _logger.debug

BABEL_GROUP = 'ff02::1:6'
BABEL_PORT = 6696

IMPORT_INTERVAL = 30

protocol = None


class Timeout:
    done = False

    def __init__(self, lsi, t, cb, a):
        assert cb is not None
        self.lsi = lsi
        self.t = t
        self.cb = cb
        self.a = a
        _debug('%s Timeout %s', self, cb)

    def cancel(self):
        assert not self.done
        assert self in self.lsi.timeouts
        _debug('%s Timeout.cancel', self)
        self.lsi.timeouts.remove(self)
        self.done = True

    def run(self):
        assert not self.done
        assert self in self.lsi.timeouts
        _debug('%s Timeout.run %s', self, self.cb)
        self.cb(*self.a)
        self.lsi.timeouts.remove(self)
        self.done = True


class LinuxSystemInterface(SystemInterface):
    def __init__(self):
        self.timeouts = []
        self.readers = {}
        self.system('ip -6 route flush proto 42')
    time = time.time
    random = random.random

    def add_reader(self, s, cb):
        self.readers[s] = cb

    def next(self):
        if not self.timeouts:
            return
        return min([x.t for x in self.timeouts])

    def poll(self):
        while True:
            t = time.time()
            l = [x for x in self.timeouts if x.t <= t]
            if not l:
                return
            l[0].run()
            # Just run them one by one as I CBA to track the cancel
            # dependencies :p

    def loop(self):
        while True:
            self.poll()
            to = self.next() - time.time()
            if to < 0.01:
                to = 0.01
            _debug('select %s %s', self.readers.keys(), to)
            (rlist, wlist, xlist) = select.select(
                self.readers.keys(), [], [], to)
            _debug('readable %s', rlist)
            for fd in rlist:
                self.readers[fd]()

    def call_later(self, dt, cb, *a):
        o = Timeout(self, dt + self.time(), cb, a)
        self.timeouts.append(o)
        return o

    def get_rid(self):
        l = list(os.popen('ip link | grep link/ether').readlines())
        if not l:
            return bytes([random.randint(0, 255) for x in range(RID_LEN)])
        d = l[0].strip().split(' ')[1]
        b = bytes([int(x, 16) for x in d.split(':')])
        if len(b) < RID_LEN:
            b = bytes(RID_LEN-len(b)) + b
        return b

    def get_if_ip(self, ifname):
        l = list(os.popen('ip -6 addr show dev %s | grep "scope link"' % ifname))
        assert l
        return ipaddress.ip_address(l[0].strip().split(' ')[1].split('/')[0])

    def send_multicast(self, ifname, b):
        self.send_unicast(ifname, BABEL_GROUP, b)

    def send_unicast(self, ifname, ip, b):
        if isinstance(ip, ipaddress.IPv6Address):
            ip = ip.compressed
        if isinstance(ip, ipaddress.IPv4Address):
            return  # no v4!
        _debug('send_unicast %s%%%s %d bytes' % (ip, ifname, len(b)))
        ifindex = socket.if_nametoindex(ifname)
        babel.interface(ifname).s.sendto(b, (ip, BABEL_PORT, 0, ifindex))

    def set_route(self, op, prefix, blackhole=False, ifname=None, nh=None):
        af = isinstance(prefix, ipaddress.IPv4Network) and "-4" or "-6"
        if blackhole:
            cmd = 'ip %(af)s route %(op)s blackhole %(prefix)s proto 42' % locals()
        else:
            cmd = 'ip %(af)s route %(op)s %(prefix)s via %(nh)s dev %(ifname)s proto 42' % locals()
        self.system(cmd)

    def system(self, cmd):
        print('# %s' % cmd)
        os.system(cmd)


def setup_babel(iflist):
    addrinfo = socket.getaddrinfo(BABEL_GROUP, None)[0]
    group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
    s = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
    s.bind(('', BABEL_PORT))
    s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, False)

    def _f():
        data, addr = s.recvfrom(2**16)
        ads, ifname = addr[0].split('%')
        a = ipaddress.ip_address(ads)
        babel.process_inbound(ifname, a, data)
    sys.add_reader(s, _f)
    for ifname in iflist:
        ifo = babel.interface(ifname)
        ifo.s = s
        ifindex = socket.if_nametoindex(ifname)
        mreq = group_bin + struct.pack('@I', ifindex)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)


def _import_timer(relist):
    _debug('_import_timer')
    local_routes = set()
    for line in os.popen('ip -6 route'):
        if line.find('proto 42') > 0:
            continue
        _debug('considering %s', line.strip())
        matching_res = [r for r in relist if r.search(line) is not None]
        if not matching_res:
            _debug('no match')
            continue
        dst = line.strip().split()[0]
        if dst == 'default':
            dst = '::/0'
        local_routes.add(ipaddress.ip_network(dst))
    if babel.local_routes != local_routes:
        _debug('updating local routes to %s', local_routes)
        babel.local_routes = local_routes
        babel.route_selection()
    sys.call_later(IMPORT_INTERVAL, _import_timer, relist)


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('-i', '--import-re', action='append', help='Import regexp')
    ap.add_argument('-d', '--debug', action='store_true',
                    help='Enable debugging')
    ap.add_argument('ifname',
                    nargs='+',
                    help="Interfaces to listen on.")
    args = ap.parse_args()
    sys = LinuxSystemInterface()
    babel = Babel(sys)
    if args.debug:
        import logging
        logging.basicConfig(level=logging.DEBUG)

    setup_babel(args.ifname)
    if args.import_re:
        _import_timer(list([re.compile(x) for x in args.import_re]))
    sys.loop()
