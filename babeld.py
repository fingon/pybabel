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
# Last modified: Thu Mar 26 01:10:07 2015 mstenber
# Edit time:     114 min
#
"""

Leveraging the pybabel module, minimalist routing daemon.

"""

from pybabel.babel import SystemInterface, Babel

import time
import random
import os
import socket
import ipaddress
import struct
import select

import logging
_logger = logging.getLogger(__name__)
_debug = _logger.debug


BABEL_GROUP = 'ff02::1:6'
BABEL_PORT = 6696

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
    time = time.time
    random = random.random
    def add_reader(self, s, cb):
        self.readers[s] = cb
    def next(self):
        if not self.timeouts: return
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
            (rlist, wlist, xlist) = select.select(self.readers.keys(), [], [], to)
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
            return bytes([1,2,3,4,5,6])
        d = l[0].strip().split(' ')[1]
        b = bytes([int(x, 16) for x in d.split(':')])
        return b
    def get_if_ip(self, ifname):
        l = list(os.popen('ip -6 addr show dev %s | grep "scope link"' % ifname))
        assert l
        return ipaddress.ip_address(l[0].strip().split(' ')[1].split('/')[0])
    def send_multicast(self, ifname, b):
        self.send_unicast(ifname, BABEL_GROUP, b)
    def send_unicast(self, ifname, ip, b):
        _debug('send_unicast %s%%%s %d bytes' % (ip, ifname, len(b)))
        #a = '%s%%%s' % (ip, ifname)
        a = ip
        babel.interface(ifname).s.sendto(b, (a, BABEL_PORT))
    def set_route(self, add, prefix, ifname, nhip):
        op = add and 'replace' or 'del'
        cmd = 'ip -6 route %(op)s %(prefix)s via %(nhip)s dev %(ifname)s' % locals()
        print('# %s' % cmd)
        os.system(cmd)

import argparse
ap = argparse.ArgumentParser()
ap.add_argument('ifname',
                nargs='*',
                help="Interfaces to listen on.")
ap.add_argument('-d', '--debug', action='store_true')
args = ap.parse_args()

sys = LinuxSystemInterface()
babel = Babel(sys)
if args.debug:
    import logging
    logging.basicConfig(level=logging.DEBUG)

def setup():
    addrinfo = socket.getaddrinfo(BABEL_GROUP, None)[0]
    group_bin = socket.inet_pton(addrinfo[0], addrinfo[4][0])
    for ifname in args.ifname:
        ifo = babel.interface(ifname)
        s = socket.socket(family=socket.AF_INET6, type=socket.SOCK_DGRAM)
        ifindex = socket.if_nametoindex(ifname)
        s.bind((ifo.ip.compressed, BABEL_PORT, 0, ifindex))
        ifo.s = s
        def _f():
            data, addr = s.recvfrom(2**16)
            a = ipaddress.ip_address(addr[0].split('%')[0])
            ifo.b.process_inbound(ifname, a, data)
            # Workaround - seems to bug somehow
            #loop.remove_reader(s.fileno())
            #loop.add_reader(s.fileno(), _f)
        #s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, ifname.encode('ascii')+bytes([0]))
        mreq = group_bin + struct.pack('@I', ifindex)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        sys.add_reader(s, _f)

setup()
sys.loop()
