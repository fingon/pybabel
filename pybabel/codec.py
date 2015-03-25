#!/usr/bin/env python
# -*- coding: utf-8 -*-
# -*- Python -*-
#
# $Id: codec.py $
#
# Author: Markus Stenberg <fingon@iki.fi>
#
# Copyright (c) 2015 Markus Stenberg
#
# Created:       Wed Mar 25 05:19:23 2015 mstenber
# Last modified: Wed Mar 25 05:44:39 2015 mstenber
# Edit time:     10 min
#
"""

This is the Babel codec module; it provides Pythonistic abstraction
for handling TLVs.

"""

import struct

class EqMixin:
    def __eq__(self, o):
        return type(o) is type(self) and self.__dict__ == o.__dict__
    def __ne_(self, o):
        return not self.__eq__(o)

class Blob(EqMixin):
    def __init__(self, **kw):
        for k, v in kw.items():
            setattr(self, k, v)
    @classmethod
    def decode(cls, x, *a, **kwa):
        o = cls()
        o.decode_buffer(x, *a, **kwa)
        return o
    def encode(self):
        raise NotImplementedError
    def decode_buffer(self, x):
        raise NotImplementedError

class CStruct(Blob):
    format = None # subclass responsibility
    keys = [] # subclass responsibility
    def __init__(self, **kw):
        Blob.__init__(self, **kw)
    def get_format(self):
        # We store this in __class__ instead of self (ugly but fast)
        if '_fmt' not in self.__class__.__dict__:
            self.__class__._fmt = struct.Struct(self.format)
        return self._fmt
    def encode(self):
        fmt = self.get_format()
        return fmt.pack(*[getattr(self, k) for k in self.keys])
    def decode_buffer(self, x, ofs=0):
        fmt = self.get_format()
        for k, v in zip(self.keys, fmt.unpack_from(x, ofs)):
            if hasattr(self, k) and getattr(self, k) == v:
                continue
            setattr(self, k, v)
    def size(self):
        return self.get_format().size

class Packet(CStruct):
    format = '>BBH'
    keys = ['magic', 'version', 'length']
    magic = 42
    version = 2
    tlvs = []
    def decode_buffer(self, x):
        CStruct.decode_buffer(self, x)
        assert self.magic == Packet.magic
        assert self.version == Packet.version
        self.tlvs = list(decode_tlvs(x[self.size():self.size()+self.length]))
    def encode(self):
        s = b''.join([x.encode() for x in self.tlvs])
        self.length = len(s)
        return CStruct.encode(self) + s

class TLV(CStruct):
    format = '>BB'
    keys = ['t', 'l']
    def encode(self):
        self.l = self.size() - 2
        return CStruct.encode(self)

class BodyTLV(TLV):
    body = b''
    def decode_buffer(self, x, ofs=0):
        TLV.decode_buffer(self, x, ofs)
        bofs = ofs + self.size()
        blen = self.l - self.size() + 2
        self.body = x[bofs:bofs+blen]
    def encode(self):
        self.l = self.size() - 2 + len(self.body)
        return CStruct.encode(self) + self.body

class PadN(BodyTLV):
    t = 1

class AckReq(TLV):
    t = 2
    format = TLV.format + 'HHH'
    keys = TLV.keys[:] + ['reserved', 'nonce', 'interval']
    reserved = 0

class Ack(TLV):
    t = 3
    format = TLV.format + 'H'
    keys = TLV.keys[:] + ['nonce']

class Hello(TLV):
    t = 4
    format = TLV.format + 'HHH'
    keys = TLV.keys[:] + ['reserved', 'seqno', 'interval']
    reserved = 0

class IHU(BodyTLV):
    t = 5
    format = TLV.format + 'BBHH'
    keys = TLV.keys[:] + ['ae', 'reserved', 'rxcost', 'interval']
    reserved = 0

class RID(TLV):
    t = 6
    format = TLV.format + 'H6s'
    keys = TLV.keys[:] + ['reserved', 'rid']
    reserved = 0

class NH(BodyTLV):
    t = 7
    format = TLV.format + 'BB'
    keys = TLV.keys[:] + ['ae', 'reserved']
    reserved = 0

class Update(BodyTLV):
    t = 8
    format = TLV.format + 'BBBBHHH'
    keys = TLV.keys[:] + ['ae', 'flags', 'plen', 'omitted', 'interval', 'seqno', 'metric']

class RouteReq(BodyTLV):
    t = 9
    format = TLV.format + 'BB'
    keys = TLV.keys[:] + ['ae', 'plen']

class SeqnoReq(BodyTLV):
    t = 10
    format = TLV.format + 'BBHBB6s'
    keys = TLV.keys[:] + ['ae', 'plen', 'seqno', 'hopcount', 'reserved', 'rid']
    reserved = 0

_tlvlist = [PadN, AckReq, Ack, Hello, IHU, RID, NH, Update, RouteReq, SeqnoReq]
_tlvs = dict([(t.t, t) for t in _tlvlist])

def decode_tlvs(x):
    i = 0
    while (i + 2) <= len(x):
        if x[i] == chr(0):
            # pad1
            i += 1
            continue
        tlv = TLV.decode(x, i)
        if tlv.t in _tlvs:
            yield _tlvs[tlv.t].decode(x, i)
        i += tlv.size() + tlv.l


