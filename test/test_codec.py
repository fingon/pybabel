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
# Last modified: Wed Mar 25 10:13:45 2015 mstenber
# Edit time:     21 min
#
"""

Play with the codec

"""

from pybabel.codec import *

def test_packet():
    Packet.decode(Packet().encode())
    tlvs = [Ack(nonce=123), PadN(body=b'12')]
    assert Packet.decode(Packet(tlvs=tlvs).encode()).tlvs == tlvs

def test_tlv_endecode():
    for cl, a in [
        (PadN, {'body': b'12'}),
        (AckReq, {'nonce': 123, 'interval': 234}),
        (Ack, {'nonce': 123}),
        (Hello, {'seqno': 123, 'interval': 234}),
        (IHU, {'ae': 2, 'rxcost': 345, 'interval': 456}),
        (RID, {'rid': b'123456'}),
        (NH, {'ae': 1}),
        (Update, {'ae': 2, 'flags': 2, 'plen': 3, 'omitted': 4,
                  'interval': 345, 'seqno': 456, 'metric': 567}),
        (RouteReq, {'ae': 2, 'plen': 3}),
        (SeqnoReq, {'ae': 2, 'plen': 3, 'seqno': 2345, 'hopcount': 3,
                    'rid': b'123456'}),
        ]:
        o0 = cl(**a)
        b = o0.encode()
        o1 = cl.decode(b)
        l = list(decode_tlvs(b))
        assert len(l) == 1
        o2 = l[0]
        for k, v in a.items():
            assert getattr(o1, k) == v
        assert o0 == o1, '%s != %s' % (o0.__dict__, o1.__dict__)
        assert o0 == o2


def test_prefix():
    p = ipaddress.ip_network('fe80::/64')
    t = PadN(**prefix_to_tlv_args(p))
    p2 = tlv_to_prefix(t)
    assert p == p2

    p = ipaddress.ip_network('1.2.3.0/24')
    t = PadN(**prefix_to_tlv_args(p))
    p2 = tlv_to_prefix(t)
    assert p == p2

def test_ip_ll():
    for a in [ipaddress.ip_address('fe80::1'),
              ipaddress.ip_address('dead:beef::2'),
              ipaddress.ip_address('1.2.3.4')]:
        t = PadN(**ip_to_tlv_args(a))
        a2 = tlv_to_ip_or_ll(t)
        assert a == a2


