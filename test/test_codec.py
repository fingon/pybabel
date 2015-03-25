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
# Last modified: Wed Mar 25 05:46:33 2015 mstenber
# Edit time:     11 min
#
"""

Play with the codec

"""

from pybabel.codec import *

def test_base():
    Packet.decode(Packet().encode())
    tlvs = [Ack(nonce=123)]
    assert Packet.decode(Packet(tlvs=tlvs).encode()).tlvs == tlvs

def test_tlv_endecode():
    for cl, a in [
        (Ack, {'nonce': 123}),
        (PadN, {'body': b'12'})
        ]:
        o0 = cl(**a)
        b = o0.encode()
        o1 = cl.decode(b)
        l = list(decode_tlvs(b))
        assert len(l) == 1
        o2 = l[0]
        for k, v in a.items():
            assert getattr(o1, k) == v
        assert o0 == o1 and o0 == o2


