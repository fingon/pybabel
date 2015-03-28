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
# Last modified: Fri Mar 27 22:01:19 2015 mstenber
# Edit time:     76 min
#
"""

This is the Babel codec module; it provides Pythonistic abstraction
for handling TLVs.

"""

import struct
import ipaddress

RID_LEN = 8
MTU_ISH = 1400 # random MTU we use for splitting TLVs when we send stuff

UPDATE_FLAG_SET_DEFAULT_PREFIX=0x80
UPDATE_FLAG_SET_DEFAULT_RID=0x40

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
    def copy(self):
        return self.__class__(**self.__dict__)
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

def _decode_error(desc, x):
    raise ValueError('%s in %s' % (desc, x))

class Packet(CStruct):
    format = '>BBH'
    keys = ['magic', 'version', 'length']
    magic = 42
    version = 2
    tlvs = []
    def decode_buffer(self, x):
        CStruct.decode_buffer(self, x)
        if self.magic != Packet.magic: _decode_error("wrong magic", self)
        if self.version != Packet.version: _decode_error("wrong version", self)
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
# local -> TLV

def ip_to_tlv_args(ip):
    if ip.is_link_local:
        return ll_to_tlv_args(ip)
    b = ip.packed
    return {'ae': len(b) == 4 and 1 or 2, 'body': b}

def ll_to_tlv_args(ip):
    b = ip.packed[8:]
    if not b: _decode_error("non-IPV4 address in ll_to_tlv_args", ip)
    return {'ae': 3, 'body': b}

def prefix_to_tlv_args(prefix):
    oplen = prefix.prefixlen
    plen = (oplen+7)//8
    b = prefix.network_address.packed[:plen]
    return {'ae': isinstance(prefix, ipaddress.IPv4Network) and 1 or 2, 'plen': oplen, 'body': b}

# TLV -> local
_p_ae2len = {1: 4, 2: 16}

def tlv_to_prefix(tlv):
    if tlv.ae not in _p_ae2len: _decode_error("unsupported af in tlv_to_prefix", tlv)
    el = _p_ae2len[tlv.ae] # expected length
    if tlv.plen:
        sl = (tlv.plen + 7)//8
        if len(tlv.body) < sl: _decode_error("too short prefix", tlv)
        b = tlv.body[:sl]
    else:
        b = b''
    b = b + bytes(el - len(b))
    na = ipaddress.ip_address(b)
    return ipaddress.ip_network('%s/%d' % (na.compressed, tlv.plen))

_ae2len = {1: 4, 2: 16, 3: 8}
def tlv_to_ip_or_ll(tlv):
    if tlv.ae not in _ae2len: _decode_error("unsupported af in tlv_to_ip_or_ll", tlv)
    el = _ae2len[tlv.ae] # expected length
    b = tlv.body[:el]
    if tlv.ae in [1, 2]:
        return ipaddress.ip_address(b)
    # just 3 left
    b = ipaddress.ip_address('fe80::').packed[:8] + b
    return ipaddress.ip_address(b)

# TLV list handling

def eliminate_duplicate_rids(tlvs):
    rid = None
    for tlv in tlvs:
        if isinstance(tlv, RID):
            if rid == tlv.rid:
                continue
            rid = tlv.rid
            yield tlv
            continue
        yield tlv

def split_tlvs_to_tlv_lists(tlvs):
    c = 4 # packet header
    l = []
    rid = None
    for tlv in tlvs:
        if isinstance(tlv, RID):
            rid = tlv
        tl = len(tlv.encode())
        if tl + c > MTU_ISH:
            yield l
            c = 4
            l = []
            if rid and not isinstance(tlv, RID):
                c += tlv.size() + 2
                l.append(rid)
        c += tl
        l.append(tlv)
    if l:
        yield l

def _shared_substring_len(p1, p2):
    if not p1 or not p2: return 0
    return max([x for x in range(len(p1)) if p1[:x] == p2[:x]])

def compress_update_tlvs(tlvs):
    # As TLVs are sorted by default (in the bulk send case), simple
    # choice is simply to _always_ set the 80 bit, and use that to
    # determine the omitted part for subsequent TLVs.

    # This is done in-place, as TLVs are not used after this except to
    # be sent on the wire.
    ae_op = {1: b'', 2: b''}
    for tlv in tlvs:
        if not isinstance(tlv, Update):
            yield tlv
            continue
        tlv = tlv.copy()
        p = tlv.body
        tlv.omitted = _shared_substring_len(ae_op[tlv.ae], p)
        if tlv.omitted: tlv.body = p[tlv.omitted:]
        tlv.flags = tlv.flags | UPDATE_FLAG_SET_DEFAULT_PREFIX
        ae_op[tlv.ae] = p
        yield tlv
    return tlvs

def split_tlvs_to_packets(tlvs):
    tlvs = eliminate_duplicate_rids(tlvs)
    # SHOULD maximize size, but MUST NOT send larger than ..
    for tlvs in split_tlvs_to_tlv_lists(tlvs):
        yield Packet(tlvs=compress_update_tlvs(tlvs)).encode()
