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
# Last modified: Fri Mar 27 13:46:32 2015 mstenber
# Edit time:     56 min
#
"""

This is the Babel codec module; it provides Pythonistic abstraction
for handling TLVs.

"""

import struct
import ipaddress

RID_LEN = 8

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
    arkeys = None # additional repr-keys
    def __init__(self, **kw):
        Blob.__init__(self, **kw)
    def __repr__(self):
        return '%s(%s)' % (self.__class__.__name__,
                           ', '.join(['%s=%s' % (k, v) for k, v in self.__dict__.items() if k in self.keys or k in self.arkeys]))
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
        if self.magic != Packet.magic: raise ValueError("wrong magic")
        if self.version != Packet.version: raise ValueError("wrong version")
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
    arkeys = ['body']
    body = b''
    def decode_buffer(self, x, ofs=0):
        TLV.decode_buffer(self, x, ofs)
        bofs = ofs + self.size()
        blen = self.l - self.size() + 2
        b = x[bofs:bofs+blen]
        if b != self.body:
            self.body = b
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
    format = TLV.format + 'H%ss' % RID_LEN
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
    format = TLV.format + 'BBHBB%ss' % RID_LEN
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

# Conversion of addresses:
# local -> local

def ip_to_tlv_args(ip):
    if ip.is_link_local:
        return ll_to_tlv_args(ip)
    b = ip.packed
    return {'ae': len(b) == 4 and 1 or 2, 'body': b}

def ll_to_tlv_args(ip):
    b = ip.packed[8:]
    if not b: raise ValueError("non-IPV4 address in ll_to_tlv_args")
    return {'ae': 3, 'body': b}

def prefix_to_tlv_args(prefix):
    oplen = prefix.prefixlen
    plen = (oplen+7)//8
    b = prefix.network_address.packed[:plen]
    return {'ae': isinstance(prefix, ipaddress.IPv4Network) and 1 or 2, 'plen': oplen, 'body': b}

# TLV -> local
_p_ae2len = {1: 4, 2: 16}

def tlv_to_prefix(tlv):
    if tlv.ae not in _p_ae2len: raise ValueError("unsupported af in tlv_to_prefix")
    el = _p_ae2len[tlv.ae] # expected length
    if tlv.plen:
        sl = (tlv.plen + 7)//8
        if len(tlv.body) < sl: raise ValueError("too short prefix")
        b = tlv.body[:sl]
    else:
        b = b''
    b = b + bytes(el - len(b))
    na = ipaddress.ip_address(b)
    return ipaddress.ip_network('%s/%d' % (na.compressed, tlv.plen))

_ae2len = {1: 4, 2: 16, 3: 8}
def tlv_to_ip_or_ll(tlv):
    if tlv.ae not in _ae2len: raise ValueError("unsupported af in tlv_to_ip_or_ll")
    el = _ae2len[tlv.ae] # expected length
    b = tlv.body[:el]
    if tlv.ae in [1, 2]:
        return ipaddress.ip_address(b)
    # just 3 left
    b = ipaddress.ip_address('fe80::').packed[:8] + b
    return ipaddress.ip_address(b)
