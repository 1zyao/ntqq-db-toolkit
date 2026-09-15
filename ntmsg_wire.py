# -*- coding: utf-8 -*-
"""NTQQ 消息体（40800）最小 wire-format 解析器。

字段定义来自 QQBackup/nt_msg_db_util 的 msgdb/proto/c2c_40800.proto
（不依赖 protobuf 运行时）。只用得上 40800 / 45001 / 45002 / 45101 / 45815 /
45600 / 45411 / 47703 / 47710 / 47713 / 49154 / 49155 等少量字段。
"""
from __future__ import annotations

import struct

# 关注字段
F_CONTENT = 40800        # MsgBody.content (repeated MsgContent)
F_CONTENT_TYPE = 45002   # MsgContent.content_type
F_TEXT = 45101           # MsgContent.text
F_TEXT_FALLBACK = 45815  # repeated bytes
F_STICKER = 45600
F_IMG_W = 45411
F_IMG_H = 45412
F_FILENAME = 45402
F_NC_UID = 47703
F_REF_MSG = 47710
F_REF_SUMMARY = 47713
F_EXT_PROTO = 49154
F_EXT_TS = 49155


def parse_wire(buf: bytes):
    """返回 [(field_no, wire_type, value)]；value 为 int(0/1/5) 或 bytes(2)。"""
    out = []
    i = 0
    n = len(buf)
    while i < n:
        # varint tag
        tag = 0
        sh = 0
        while True:
            if i >= n or sh > 63:
                raise ValueError('bad tag')
            b = buf[i]
            i += 1
            tag |= (b & 0x7f) << sh
            if not b & 0x80:
                break
            sh += 7
        fno, wire = tag >> 3, tag & 7
        if fno == 0:
            raise ValueError('field 0')
        if wire == 0:
            v = 0
            sh = 0
            while True:
                if i >= n or sh > 63:
                    raise ValueError('bad varint')
                b = buf[i]
                i += 1
                v |= (b & 0x7f) << sh
                if not b & 0x80:
                    break
                sh += 7
            out.append((fno, 0, v))
        elif wire == 2:
            ln = 0
            sh = 0
            while True:
                if i >= n or sh > 63:
                    raise ValueError('bad len')
                b = buf[i]
                i += 1
                ln |= (b & 0x7f) << sh
                if not b & 0x80:
                    break
                sh += 7
            if i + ln > n:
                raise ValueError('truncated')
            out.append((fno, 2, buf[i:i + ln]))
            i += ln
        elif wire == 5:
            if i + 4 > n:
                raise ValueError('truncated i32')
            out.append((fno, 5, struct.unpack('<I', buf[i:i + 4])[0]))
            i += 4
        elif wire == 1:
            if i + 8 > n:
                raise ValueError('truncated i64')
            out.append((fno, 1, struct.unpack('<Q', buf[i:i + 8])[0]))
            i += 8
        else:
            raise ValueError('wire %d' % wire)
    return out


def _utf8(b: bytes) -> str:
    return b.decode('utf-8', 'replace')


def parse_msg_body(blob: bytes):
    """把 40800 blob 解析为 [ {content_type, text, ...}, ... ]（每个 MsgContent 一项）。"""
    items = []
    if not blob:
        return items
    try:
        top = parse_wire(blob)
    except ValueError:
        return items
    for fno, wire, val in top:
        if fno == F_CONTENT and wire == 2:
            items.append(parse_content(val))
    return items


def parse_content(buf: bytes) -> dict:
    c = {'content_type': 0, 'text': '', 'fallbacks': [], 'sticker': b'',
         'img_w': 0, 'img_h': 0, 'filename': '', 'nc_uid': '',
         'ref_summary': '', 'proto_ver': '', 'ts': 0}
    try:
        fields = parse_wire(buf)
    except ValueError:
        return c
    for fno, wire, val in fields:
        if fno == F_CONTENT_TYPE and wire == 0:
            c['content_type'] = val
        elif fno == F_TEXT and wire == 2:
            c['text'] = _utf8(val)
        elif fno == F_TEXT_FALLBACK and wire == 2:
            c['fallbacks'].append(_utf8(val))
        elif fno == F_STICKER and wire == 2:
            c['sticker'] = val
        elif fno == F_IMG_W and wire == 0:
            c['img_w'] = val
        elif fno == F_IMG_H and wire == 0:
            c['img_h'] = val
        elif fno == F_FILENAME and wire == 2:
            c['filename'] = _utf8(val)
        elif fno == F_NC_UID and wire == 2:
            c['nc_uid'] = _utf8(val)
        elif fno == F_REF_SUMMARY and wire == 2:
            c['ref_summary'] = _utf8(val)
        elif fno == F_EXT_PROTO and wire == 2:
            c['proto_ver'] = _utf8(val)
        elif fno == F_EXT_TS and wire == 0:
            c['ts'] = val
    return c


def message_view(blob: bytes, msg_type: int = 0):
    """给出一条消息的 (kind, text) —— kind ∈ text/sticker/image/video/file/reply/other。"""
    items = parse_msg_body(blob)
    if not items:
        return ('empty', '')
    texts = [it['text'] for it in items if it['text']]
    if texts:
        return ('text', '\n'.join(texts))
    c = items[0]
    ct = c['content_type']
    if ct == 5 or c['sticker']:
        fb = c['fallbacks'][0] if c['fallbacks'] else ''
        return ('sticker', fb)
    if ct == 2 and (c['img_w'] or c['img_h']):
        return ('image', '')
    if ct == 2:
        return ('video', '')
    if ct == 3 or msg_type == 3:
        return ('file', c['filename'])
    if ct == 16 or msg_type == 8:
        return ('forward', '')
    return ('other(c%d)' % ct, '')
