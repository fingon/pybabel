#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: test_codec.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Wed Mar 25 05:23:14 2015 mstenber
# Last modified: Fri Mar 27 21:54:29 2015 mstenber
# Edit time:     43 min
#
"""

Play with the codec

"""

from pybabel.codec import *

import binascii

def test_packet():
    Packet.decode(Packet().encode())
    tlvs = [Ack(nonce=123), PadN(body=b'12')]
    assert Packet.decode(Packet(tlvs=tlvs).encode()).tlvs == tlvs

def test_repr():
    t = PadN(body=b'12')
    assert repr(t) == "PadN(body=b'12')"


def test_tlv_endecode():
    for cl, a in [
        (PadN, {'body': b'12'}),
        (AckReq, {'nonce': 123, 'interval': 234}),
        (Ack, {'nonce': 123}),
        (Hello, {'seqno': 123, 'interval': 234}),
        (IHU, {'ae': 2, 'rxcost': 345, 'interval': 456}),
        (RID, {'rid': b'12345678'}),
        (NH, {'ae': 1}),
        (Update, {'ae': 2, 'flags': 2, 'plen': 3, 'omitted': 4,
                  'interval': 345, 'seqno': 456, 'metric': 567}),
        (RouteReq, {'ae': 2, 'plen': 3}),
        (SeqnoReq, {'ae': 2, 'plen': 3, 'seqno': 2345, 'hopcount': 3,
                    'rid': b'12345678'}),
        ]:
        o0 = cl(**a)
        b = o0.encode()
        o1 = cl.decode(b)
        l = list(decode_tlvs(b))
        assert len(l) == 1
        o2 = l[0]
        for k, v in a.items():
            v2 = getattr(o1, k)
            assert v2 == v, '%s - %s != %s' % (k, v, v2)
        assert o0 == o1, '%s != %s' % (o0.__dict__, o1.__dict__)
        assert o0 == o2
        # Make sure decoder does not choke if we have extra garbage at end too
        nb = bytes([b[0], b[1]+42]) + b[2:] + bytes(42)
        o3 = cl.decode(nb)
        assert o3

    # seqno from real Babel
    # fdf6.. = prefix

    #                       T L AEP SEQ H R RID______
    b = binascii.unhexlify('0a140230cfec7f00648e8a067cb3db0afdf6e0b2026a')
    l = list(decode_tlvs(b))
    assert len(l) == 1


def test_prefix():
    p = ipaddress.ip_network('fe80::/64')
    t = PadN(**prefix_to_tlv_args(p))
    p2 = tlv_to_prefix(t)
    assert p == p2

    p = ipaddress.ip_network('1.2.3.0/24')
    t = PadN(**prefix_to_tlv_args(p))
    p2 = tlv_to_prefix(t)
    assert p == p2

    # Make sure extra body content is ignored
    t.body = t.body + bytes(42)
    p2 = tlv_to_prefix(t)
    assert p == p2

def test_ip_ll():
    for a in [ipaddress.ip_address('fe80::1'),
              ipaddress.ip_address('dead:beef::2'),
              ipaddress.ip_address('1.2.3.4')]:
        t = PadN(**ip_to_tlv_args(a))
        a2 = tlv_to_ip_or_ll(t)
        assert a == a2

        # Make sure extra body content is ignored
        t.body = t.body + bytes(42)
        a2 = tlv_to_ip_or_ll(t)
        assert a == a2


def test_compression():
    p0 = ipaddress.ip_network('dead:beef::/48')
    p1 = ipaddress.ip_network('dead:beef:1::/48')
    p2 = ipaddress.ip_network('dead:beef:2::/48')
    p3 = ipaddress.ip_network('feed:dead::/32')
    tlvs = [Update(flags=0, omitted=0, interval=1, seqno=123,
                   metric=1, **prefix_to_tlv_args(p0)),
            Update(flags=0, omitted=0, interval=1, seqno=123,
                   metric=1, **prefix_to_tlv_args(p1)),
            Update(flags=0, omitted=0, interval=1, seqno=123,
                   metric=1, **prefix_to_tlv_args(p2)),
            Update(flags=0, omitted=0, interval=1, seqno=123,
                   metric=1, **prefix_to_tlv_args(p3)),
            ]
    tlvs2 = list(compress_update_tlvs(tlvs))
    assert tlvs[1].omitted == 0
    assert tlvs2[1].omitted == 5
    assert tlvs2[1].body == bytes([1])
    assert tlvs2[2].omitted == 5
    assert tlvs2[2].body == bytes([2])
    assert tlvs2[3].omitted == 0
    assert tlvs2[3].body == bytes([0xfe, 0xed, 0xde, 0xad])

def test_long():
    r = RID(rid=b'')
    u = Update(ae=0, omitted=0, flags=0, plen=0, interval=0, seqno=0, metric=0)
    ll = split_tlvs_to_tlv_lists([r] + [u] * int(MTU_ISH * 3 / 2 / (u.size() + 2)))
    ll = list(ll)
    assert len(ll) == 2
    (l1, l2) = ll
    assert l1[0] == r
    assert l2[0] == r

