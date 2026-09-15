#!/usr/bin/env python3
"""Build the embedded 75+ FPS Stormy Castle SWF from the untouched 0.swf.

This is intentionally a small, self-contained ABC/SWF patcher. It keeps 0.swf
as the source, changes only the copy, and adds the FPS panel as AVM2 code on
Main. No HTML/launcher overlay is involved.
"""
from __future__ import annotations

import copy
import hashlib
import io
import struct
import sys
import zlib
from pathlib import Path


# ---------------------------------------------------------------------------
# ABC reader/writer. The reader shape mirrors the analysis parser used while
# reverse engineering the file, but this copy is able to serialize it again.

class Reader:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def u8(self) -> int:
        v = self.data[self.pos]
        self.pos += 1
        return v

    def u16(self) -> int:
        v = struct.unpack_from('<H', self.data, self.pos)[0]
        self.pos += 2
        return v

    def u30(self) -> int:
        value = 0
        shift = 0
        while True:
            b = self.u8()
            value |= (b & 0x7f) << shift
            if not b & 0x80:
                return value
            shift += 7
            if shift > 35:
                raise ValueError('invalid U30')

    def f64(self) -> bytes:
        value = self.data[self.pos:self.pos + 8]
        self.pos += 8
        return value

    def take(self, n: int) -> bytes:
        value = self.data[self.pos:self.pos + n]
        self.pos += n
        return value


def u30(value: int) -> bytes:
    if value < 0:
        value &= 0xffffffff
    out = bytearray()
    # U30 values in this file are all within the legal range. The final byte
    # has no continuation bit.
    while value >= 0x80:
        out.append((value & 0x7f) | 0x80)
        value >>= 7
    out.append(value & 0x7f)
    return bytes(out)


def parse_abc(data: bytes) -> dict:
    r = Reader(data)
    x = {'minor': r.u16(), 'major': r.u16()}
    x['ints'] = [None] + [r.u30() for _ in range(r.u30() - 1)]
    x['uints'] = [None] + [r.u30() for _ in range(r.u30() - 1)]
    x['doubles'] = [None] + [r.f64() for _ in range(r.u30() - 1)]
    x['strings'] = [None]
    for _ in range(r.u30() - 1):
        length = r.u30()
        x['strings'].append(r.take(length).decode('utf-8', 'surrogateescape'))
    x['namespaces'] = [None]
    for _ in range(r.u30() - 1):
        x['namespaces'].append((r.u8(), r.u30()))
    x['ns_sets'] = [None]
    for _ in range(r.u30() - 1):
        x['ns_sets'].append([r.u30() for _ in range(r.u30())])
    x['multinames'] = [None]
    for _ in range(r.u30() - 1):
        kind = r.u8()
        if kind in (0x07, 0x0d):
            item = (kind, r.u30(), r.u30())
        elif kind in (0x0f, 0x10):
            item = (kind, r.u30())
        elif kind in (0x11, 0x12):
            item = (kind,)
        elif kind in (0x09, 0x0e):
            item = (kind, r.u30(), r.u30())
        elif kind in (0x1b, 0x1c):
            item = (kind, r.u30())
        elif kind == 0x1d:
            name = r.u30()
            item = (kind, name, [r.u30() for _ in range(r.u30())])
        else:
            raise ValueError(f'unknown multiname kind 0x{kind:x}')
        x['multinames'].append(item)

    def read_method() -> dict:
        param_count = r.u30()
        item = {
            'param_count': param_count,
            'return': r.u30(),
            'params': [r.u30() for _ in range(param_count)],
            'name': r.u30(),
            'flags': r.u8(),
        }
        if item['flags'] & 8:
            item['optional'] = [(r.u30(), r.u8()) for _ in range(r.u30())]
        if item['flags'] & 128:
            item['param_names'] = [r.u30() for _ in range(param_count)]
        return item

    x['methods'] = []
    for index in range(r.u30()):
        item = read_method()
        item['index'] = index
        x['methods'].append(item)

    x['metadata'] = []
    for _ in range(r.u30()):
        name = r.u30()
        x['metadata'].append((name, [(r.u30(), r.u30()) for _ in range(r.u30())]))

    def read_traits() -> list[dict]:
        traits = []
        for _ in range(r.u30()):
            name = r.u30()
            kind_attr = r.u8()
            kind = kind_attr & 0x0f
            attrs = kind_attr >> 4
            item = {'name': name, 'kind': kind, 'attrs': attrs}
            if kind in (0, 6):
                item.update(slot_id=r.u30(), type=r.u30(), vindex=r.u30())
                if item['vindex']:
                    item['vkind'] = r.u8()
            elif kind in (1, 2, 3):
                item.update(disp_id=r.u30(), method=r.u30())
            elif kind in (4, 5):
                item.update(disp_id=r.u30(), class_=r.u30())
            else:
                raise ValueError(f'unknown trait kind {kind}')
            if attrs & 4:
                item['metadata'] = [r.u30() for _ in range(r.u30())]
            traits.append(item)
        return traits

    x['instances'] = []
    instance_count = r.u30()
    for index in range(instance_count):
        name = r.u30()
        superclass = r.u30()
        flags = r.u8()
        protected = r.u30() if flags & 8 else None
        interfaces = [r.u30() for _ in range(r.u30())]
        x['instances'].append({
            'index': index, 'name': name, 'super': superclass,
            'flags': flags, 'protected': protected, 'interfaces': interfaces,
            'iinit': r.u30(), 'traits': read_traits(),
        })

    x['classes'] = []
    for index in range(instance_count):
        x['classes'].append({'index': index, 'cinit': r.u30(), 'traits': read_traits()})

    x['scripts'] = []
    for index in range(r.u30()):
        x['scripts'].append({'index': index, 'init': r.u30(), 'traits': read_traits()})

    x['bodies'] = []
    for index in range(r.u30()):
        item = {
            'index': index,
            'method': r.u30(),
            'maxstack': r.u30(),
            'locals': r.u30(),
            'init_scope': r.u30(),
            'max_scope': r.u30(),
        }
        code_length = r.u30()
        item['code'] = r.take(code_length)
        exceptions = []
        for _ in range(r.u30()):
            exceptions.append({
                'from': r.u30(), 'to': r.u30(), 'target': r.u30(),
                'exc_type': r.u30(), 'var_name': r.u30(),
            })
        item['exceptions'] = exceptions
        item['traits'] = read_traits()
        x['bodies'].append(item)

    if r.pos != len(data):
        raise ValueError(f'ABC trailing bytes: {r.pos} of {len(data)}')
    return x


def write_traits(out: bytearray, traits: list[dict]) -> None:
    out += u30(len(traits))
    for item in traits:
        out += u30(item['name'])
        out.append((item['attrs'] << 4) | item['kind'])
        kind = item['kind']
        if kind in (0, 6):
            out += u30(item['slot_id']) + u30(item['type']) + u30(item['vindex'])
            if item['vindex']:
                out.append(item['vkind'])
        elif kind in (1, 2, 3):
            out += u30(item['disp_id']) + u30(item['method'])
        elif kind in (4, 5):
            out += u30(item['disp_id']) + u30(item['class_'])
        else:
            raise ValueError(f'unknown trait kind {kind}')
        if item['attrs'] & 4:
            metadata = item.get('metadata', [])
            out += u30(len(metadata))
            for value in metadata:
                out += u30(value)


def serialize_abc(x: dict) -> bytes:
    out = bytearray(struct.pack('<HH', x['minor'], x['major']))

    def write_pool(values, writer):
        # ABC uses count 0 for an empty pool (the implicit zero entry is not
        # serialized); non-empty pools include the implicit slot in count.
        out.extend(u30(0 if len(values) == 1 else len(values)))
        for value in values[1:]:
            writer(value)

    write_pool(x['ints'], lambda value: out.extend(u30(value)))
    write_pool(x['uints'], lambda value: out.extend(u30(value)))
    write_pool(x['doubles'], lambda value: out.extend(value))

    out += u30(len(x['strings']))
    for value in x['strings'][1:]:
        encoded = value.encode('utf-8', 'surrogateescape')
        out += u30(len(encoded)) + encoded

    out += u30(len(x['namespaces']))
    for kind, name in x['namespaces'][1:]:
        out.append(kind)
        out += u30(name)

    out += u30(len(x['ns_sets']))
    for values in x['ns_sets'][1:]:
        out += u30(len(values))
        for value in values:
            out += u30(value)

    out += u30(len(x['multinames']))
    for item in x['multinames'][1:]:
        kind = item[0]
        out.append(kind)
        if kind in (0x07, 0x0d):
            out += u30(item[1]) + u30(item[2])
        elif kind in (0x0f, 0x10):
            out += u30(item[1])
        elif kind in (0x11, 0x12):
            pass
        elif kind in (0x09, 0x0e):
            out += u30(item[1]) + u30(item[2])
        elif kind in (0x1b, 0x1c):
            out += u30(item[1])
        elif kind == 0x1d:
            out += u30(item[1]) + u30(len(item[2]))
            for value in item[2]:
                out += u30(value)
        else:
            raise ValueError(f'unknown multiname kind 0x{kind:x}')

    out += u30(len(x['methods']))
    for item in x['methods']:
        out += u30(item['param_count']) + u30(item['return'])
        for value in item['params']:
            out += u30(value)
        out += u30(item['name'])
        out.append(item['flags'])
        if item['flags'] & 8:
            optional = item.get('optional', [])
            out += u30(len(optional))
            for value, kind in optional:
                out += u30(value) + bytes([kind])
        if item['flags'] & 128:
            for value in item.get('param_names', []):
                out += u30(value)

    out += u30(len(x['metadata']))
    for name, items in x['metadata']:
        out += u30(name) + u30(len(items))
        for key, value in items:
            out += u30(key) + u30(value)

    out += u30(len(x['instances']))
    for item in x['instances']:
        out += u30(item['name']) + u30(item['super']) + bytes([item['flags']])
        if item['flags'] & 8:
            out += u30(item['protected'])
        out += u30(len(item['interfaces']))
        for value in item['interfaces']:
            out += u30(value)
        out += u30(item['iinit'])
        write_traits(out, item['traits'])

    for item in x['classes']:
        out += u30(item['cinit'])
        write_traits(out, item['traits'])

    out += u30(len(x['scripts']))
    for item in x['scripts']:
        out += u30(item['init'])
        write_traits(out, item['traits'])

    out += u30(len(x['bodies']))
    for item in x['bodies']:
        out += u30(item['method']) + u30(item['maxstack']) + u30(item['locals'])
        out += u30(item['init_scope']) + u30(item['max_scope'])
        out += u30(len(item['code'])) + item['code']
        out += u30(len(item['exceptions']))
        for exc in item['exceptions']:
            out += u30(exc['from']) + u30(exc['to']) + u30(exc['target'])
            out += u30(exc['exc_type']) + u30(exc['var_name'])
        write_traits(out, item['traits'])
    return bytes(out)


# ---------------------------------------------------------------------------
# Small AVM2 assembler. Only the ordinary AVM2 instructions used by the new
# panel are exposed. Branch displacements are relative to the next opcode.

class Assembler:
    def __init__(self):
        self.code = bytearray()
        self.labels = {}
        self.fixups = []

    def label(self, name: str) -> None:
        if name in self.labels:
            raise ValueError(f'duplicate label {name}')
        self.labels[name] = len(self.code)

    def emit(self, opcode: int, *operands: bytes) -> None:
        self.code.append(opcode)
        for operand in operands:
            self.code += operand

    def pool(self, opcode: int, index: int) -> None:
        self.emit(opcode, u30(index))

    def getlex(self, index: int) -> None:
        self.pool(0x60, index)

    def branch(self, opcode: int, label: str) -> None:
        at = len(self.code)
        self.code.append(opcode)
        self.code += b'\0\0\0'
        self.fixups.append((at, label))

    def finish(self) -> bytes:
        for at, label in self.fixups:
            if label not in self.labels:
                raise ValueError(f'unknown label {label}')
            # s24 is relative to the address immediately after the operand.
            displacement = self.labels[label] - (at + 4)
            if not -(1 << 23) <= displacement < (1 << 23):
                raise ValueError('branch too far')
            self.code[at + 1:at + 4] = struct.pack('<i', displacement)[:3]
        return bytes(self.code)

    def getlocal(self, index: int) -> None:
        if index == 0: self.emit(0xd0)
        elif index == 1: self.emit(0xd1)
        elif index == 2: self.emit(0xd2)
        elif index == 3: self.emit(0xd3)
        else: self.emit(0x62, u30(index))

    def setlocal(self, index: int) -> None:
        if index == 0: self.emit(0xd4)
        elif index == 1: self.emit(0xd5)
        elif index == 2: self.emit(0xd6)
        elif index == 3: self.emit(0xd7)
        else: self.emit(0x63, u30(index))

    def push_number(self, value: int) -> None:
        if -128 <= value <= 127:
            self.emit(0x24, struct.pack('<b', value))
        elif 0 <= value <= 0x3fffffff:
            self.emit(0x25, u30(value))
        else:
            raise ValueError(f'number needs a pool: {value}')


# ---------------------------------------------------------------------------
# Patch construction.

class Pool:
    def __init__(self, abc: dict):
        self.x = abc

    def string(self, value: str) -> int:
        try:
            return self.x['strings'].index(value)
        except ValueError:
            self.x['strings'].append(value)
            return len(self.x['strings']) - 1

    def int(self, value: int) -> int:
        try:
            return self.x['ints'].index(value)
        except ValueError:
            self.x['ints'].append(value)
            return len(self.x['ints']) - 1

    def qname(self, namespace: int, name: str) -> int:
        name_index = self.string(name)
        item = (0x07, namespace, name_index)
        try:
            return self.x['multinames'].index(item)
        except ValueError:
            self.x['multinames'].append(item)
            return len(self.x['multinames']) - 1


def method_trait(name_qname: int, method_index: int) -> dict:
    return {'name': name_qname, 'kind': 1, 'attrs': 0, 'disp_id': 0, 'method': method_index}


def body(method_index: int, code: bytes, maxstack: int, locals_: int,
         init_scope: int = 9, max_scope: int = 10) -> dict:
    return {
        'index': -1, 'method': method_index, 'maxstack': maxstack,
        'locals': locals_, 'init_scope': init_scope, 'max_scope': max_scope,
        'code': code, 'exceptions': [], 'traits': [],
    }


def make_open_method(p: Pool, q: dict, strings: dict, colors: dict) -> bytes:
    a = Assembler()
    # locals: 0=this, 1=KeyboardEvent, 2=panel, 3=temp,
    # 4=input, 5=button/text-field temp
    a.getlocal(0); a.emit(0x30)
    # The panel is opened by the right Shift key: keyCode 16 plus the
    # KeyboardEvent RIGHT location (2). This avoids relying on a browser's
    # context-menu/right-click policy.
    a.getlocal(1); a.pool(0x66, q['keyCode']); a.push_number(16); a.branch(0x14, 'not_right_shift')
    a.getlocal(1); a.pool(0x66, q['keyLocation']); a.push_number(2); a.branch(0x14, 'not_right_shift')
    a.getlocal(0); a.pool(0x2c, strings['fpsPanel']); a.emit(0x46); a.code += u30(q['getChildByName']) + u30(1)
    a.emit(0xd6)  # setlocal_2
    a.getlocal(2); a.branch(0x12, 'create')  # iffalse
    a.getlocal(2); a.getlex(q['Math']); a.getlex(q['stage']); a.pool(0x66, q['mouseX']); a.push_number(540); a.emit(0x46); a.code += u30(q['min']) + u30(2); a.pool(0x61, q['x'])
    a.getlocal(2); a.getlex(q['Math']); a.getlex(q['stage']); a.pool(0x66, q['mouseY']); a.push_number(350); a.emit(0x46); a.code += u30(q['min']) + u30(2); a.pool(0x61, q['y'])
    a.getlocal(2); a.emit(0x26); a.pool(0x61, q['visible'])
    a.emit(0x47)
    a.label('create')

    # panel sprite
    a.pool(0x5d, q['Sprite']); a.emit(0x4a); a.code += u30(q['Sprite']) + u30(0)  # finddef + constructprop Sprite, 0
    a.emit(0xd6)
    a.getlocal(2); a.pool(0x2c, strings['fpsPanel']); a.pool(0x61, q['name'])
    a.getlocal(2); a.pool(0x66, q['graphics']); a.pool(0x2d, colors['panel']); a.emit(0x4f); a.code += u30(q['beginFill']) + u30(1)
    a.getlocal(2); a.pool(0x66, q['graphics']); a.push_number(0); a.push_number(0); a.push_number(260); a.push_number(250); a.emit(0x4f); a.code += u30(q['drawRect']) + u30(4)
    a.getlocal(2); a.pool(0x66, q['graphics']); a.emit(0x4f); a.code += u30(q['endFill']) + u30(0)
    a.getlocal(2); a.getlex(q['Math']); a.getlex(q['stage']); a.pool(0x66, q['mouseX']); a.push_number(540); a.emit(0x46); a.code += u30(q['min']) + u30(2); a.pool(0x61, q['x'])
    a.getlocal(2); a.getlex(q['Math']); a.getlex(q['stage']); a.pool(0x66, q['mouseY']); a.push_number(350); a.emit(0x46); a.code += u30(q['min']) + u30(2); a.pool(0x61, q['y'])
    # Keep children interactive: the header and each button disable their own
    # mouseChildren, while the panel must let events reach those controls.
    a.getlocal(2); a.emit(0x26); a.pool(0x61, q['mouseChildren'])
    a.getlocal(0); a.getlocal(2); a.emit(0x4f); a.code += u30(q['addChild']) + u30(1)

    # header sprite
    a.pool(0x5d, q['Sprite']); a.emit(0x4a); a.code += u30(q['Sprite']) + u30(0); a.emit(0xd7)
    a.getlocal(3); a.pool(0x2c, strings['fpsHeader']); a.pool(0x61, q['name'])
    a.getlocal(3); a.pool(0x66, q['graphics']); a.pool(0x2d, colors['header']); a.emit(0x4f); a.code += u30(q['beginFill']) + u30(1)
    a.getlocal(3); a.pool(0x66, q['graphics']); a.push_number(0); a.push_number(0); a.push_number(260); a.push_number(27); a.emit(0x4f); a.code += u30(q['drawRect']) + u30(4)
    a.getlocal(3); a.pool(0x66, q['graphics']); a.emit(0x4f); a.code += u30(q['endFill']) + u30(0)
    a.getlocal(3); a.emit(0x27); a.pool(0x61, q['mouseChildren'])
    a.getlocal(2); a.getlocal(3); a.emit(0x4f); a.code += u30(q['addChild']) + u30(1)

    # title text field in the header (temp local 3 is reused after header is added)
    a.pool(0x5d, q['TextField']); a.emit(0x4a); a.code += u30(q['TextField']) + u30(0); a.emit(0xd7)
    a.getlocal(3); a.pool(0x2c, strings['title']); a.pool(0x61, q['text'])
    a.getlocal(3); a.pool(0x2d, colors['white']); a.pool(0x61, q['textColor'])
    a.getlocal(3); a.push_number(8); a.pool(0x61, q['x'])
    a.getlocal(3); a.push_number(3); a.pool(0x61, q['y'])
    a.getlocal(3); a.push_number(240); a.pool(0x61, q['width'])
    a.getlocal(3); a.push_number(22); a.pool(0x61, q['height'])
    a.getlocal(3); a.emit(0x27); a.pool(0x61, q['selectable'])
    # header = panel.getChildByName(fpsHeader), then add title
    a.getlocal(2); a.pool(0x2c, strings['fpsHeader']); a.emit(0x46); a.code += u30(q['getChildByName']) + u30(1)
    a.getlocal(3); a.emit(0x4f); a.code += u30(q['addChild']) + u30(1)

    # input TextField
    a.pool(0x5d, q['TextField']); a.emit(0x4a); a.code += u30(q['TextField']) + u30(0); a.emit(0xd7)
    a.getlocal(3); a.emit(0x26); a.pool(0x61, q['border'])
    a.getlocal(3); a.emit(0x26); a.pool(0x61, q['background'])
    a.getlocal(3); a.pool(0x2c, strings['fpsInput']); a.pool(0x61, q['name'])
    a.getlocal(3); a.pool(0x2c, strings['defaultFps']); a.pool(0x61, q['text'])
    a.getlocal(3); a.pool(0x2c, strings['input']); a.pool(0x61, q['type'])
    a.getlocal(3); a.push_number(10); a.pool(0x61, q['x'])
    a.getlocal(3); a.push_number(36); a.pool(0x61, q['y'])
    a.getlocal(3); a.push_number(240); a.pool(0x61, q['width'])
    a.getlocal(3); a.push_number(24); a.pool(0x61, q['height'])
    a.getlocal(2); a.getlocal(3); a.emit(0x4f); a.code += u30(q['addChild']) + u30(1)
    # Keep the input in a local while the button sprites are built.
    a.setlocal(4)

    def add_button(name_key: str, caption_key: str, color_key: str, xx: int, yy: int, ww: int = 90) -> None:
        a.pool(0x5d, q['Sprite']); a.emit(0x4a); a.code += u30(q['Sprite']) + u30(0); a.emit(0xd7)
        a.getlocal(3); a.pool(0x2c, strings[name_key]); a.pool(0x61, q['name'])
        a.getlocal(3); a.pool(0x66, q['graphics']); a.pool(0x2d, colors[color_key]); a.emit(0x4f); a.code += u30(q['beginFill']) + u30(1)
        a.getlocal(3); a.pool(0x66, q['graphics']); a.push_number(0); a.push_number(0); a.push_number(ww); a.push_number(27); a.emit(0x4f); a.code += u30(q['drawRect']) + u30(4)
        a.getlocal(3); a.pool(0x66, q['graphics']); a.emit(0x4f); a.code += u30(q['endFill']) + u30(0)
        a.getlocal(3); a.emit(0x27); a.pool(0x61, q['mouseChildren'])
        a.getlocal(3); a.push_number(xx); a.pool(0x61, q['x'])
        a.getlocal(3); a.push_number(yy); a.pool(0x61, q['y'])
        # button label
        a.pool(0x5d, q['TextField']); a.emit(0x4a); a.code += u30(q['TextField']) + u30(0); a.emit(0x63); a.code += u30(5)
        a.getlocal(5); a.pool(0x2c, strings[caption_key]); a.pool(0x61, q['text'])
        a.getlocal(5); a.pool(0x2d, colors['white']); a.pool(0x61, q['textColor'])
        a.getlocal(5); a.push_number(5); a.pool(0x61, q['x'])
        a.getlocal(5); a.push_number(4); a.pool(0x61, q['y'])
        a.getlocal(5); a.push_number(ww - 10); a.pool(0x61, q['width'])
        a.getlocal(5); a.push_number(20); a.pool(0x61, q['height'])
        a.getlocal(5); a.emit(0x27); a.pool(0x61, q['selectable'])
        a.getlocal(3); a.getlocal(5); a.emit(0x4f); a.code += u30(q['addChild']) + u30(1)
        a.getlocal(2); a.getlocal(3); a.emit(0x4f); a.code += u30(q['addChild']) + u30(1)

    add_button('fps75', 'caption75', 'button', 10, 70)
    add_button('fps120', 'caption120', 'button', 110, 70)
    add_button('fpsApply', 'captionApply', 'apply', 10, 105)
    add_button('fpsClose', 'captionClose', 'close', 110, 105)

    # Money editor section. It is deliberately an independent input: the
    # current level is resolved only when the user presses Set money.
    a.pool(0x5d, q['TextField']); a.emit(0x4a); a.code += u30(q['TextField']) + u30(0); a.emit(0xd7)
    a.getlocal(3); a.pool(0x2c, strings['moneyLabel']); a.pool(0x61, q['text'])
    a.getlocal(3); a.pool(0x2d, colors['white']); a.pool(0x61, q['textColor'])
    a.getlocal(3); a.push_number(10); a.pool(0x61, q['x'])
    a.getlocal(3); a.push_number(140); a.pool(0x61, q['y'])
    a.getlocal(3); a.push_number(240); a.pool(0x61, q['width'])
    a.getlocal(3); a.push_number(18); a.pool(0x61, q['height'])
    a.getlocal(3); a.emit(0x27); a.pool(0x61, q['selectable'])
    a.getlocal(2); a.getlocal(3); a.emit(0x4f); a.code += u30(q['addChild']) + u30(1)

    a.pool(0x5d, q['TextField']); a.emit(0x4a); a.code += u30(q['TextField']) + u30(0); a.emit(0xd7)
    a.getlocal(3); a.emit(0x26); a.pool(0x61, q['border'])
    a.getlocal(3); a.emit(0x26); a.pool(0x61, q['background'])
    a.getlocal(3); a.pool(0x2c, strings['moneyInput']); a.pool(0x61, q['name'])
    a.getlocal(3); a.pool(0x2c, strings['defaultMoney']); a.pool(0x61, q['text'])
    a.getlocal(3); a.pool(0x2c, strings['input']); a.pool(0x61, q['type'])
    a.getlocal(3); a.push_number(10); a.pool(0x61, q['x'])
    a.getlocal(3); a.push_number(162); a.pool(0x61, q['y'])
    a.getlocal(3); a.push_number(240); a.pool(0x61, q['width'])
    a.getlocal(3); a.push_number(24); a.pool(0x61, q['height'])
    a.getlocal(2); a.getlocal(3); a.emit(0x4f); a.code += u30(q['addChild']) + u30(1)
    a.setlocal(4)
    add_button('moneyApply', 'captionMoney', 'apply', 10, 194, 240)

    # Footer text.
    a.pool(0x5d, q['TextField']); a.emit(0x4a); a.code += u30(q['TextField']) + u30(0); a.emit(0xd7)
    a.getlocal(3); a.pool(0x2c, strings['footer']); a.pool(0x61, q['text'])
    a.getlocal(3); a.pool(0x2d, colors['white']); a.pool(0x61, q['textColor'])
    a.getlocal(3); a.push_number(10); a.pool(0x61, q['x'])
    a.getlocal(3); a.push_number(228); a.pool(0x61, q['y'])
    a.getlocal(3); a.push_number(240); a.pool(0x61, q['width'])
    a.getlocal(3); a.push_number(18); a.pool(0x61, q['height'])
    a.getlocal(3); a.emit(0x27); a.pool(0x61, q['selectable'])
    a.getlocal(2); a.getlocal(3); a.emit(0x4f); a.code += u30(q['addChild']) + u30(1)

    # panel click and header drag listeners
    a.getlocal(2); a.getlex(q['MouseEvent']); a.pool(0x66, q['CLICK']); a.getlocal(0); a.pool(0x66, q['fpsEventName']); a.emit(0x4f); a.code += u30(q['addEventListener']) + u30(2)
    a.getlocal(2); a.pool(0x2c, strings['fpsHeader']); a.emit(0x46); a.code += u30(q['getChildByName']) + u30(1)
    a.getlex(q['MouseEvent']); a.pool(0x66, q['MOUSE_DOWN']); a.getlocal(0); a.pool(0x66, q['fpsEventName']); a.emit(0x4f); a.code += u30(q['addEventListener']) + u30(2)
    a.emit(0x47)
    a.label('not_right_shift')
    a.emit(0x47)
    return a.finish()


def make_event_method(p: Pool, q: dict, strings: dict, colors: dict) -> bytes:
    a = Assembler()
    # locals: 0=this, 1=Event, 2=target, 3=target name, 4=panel/number,
    # 5=InGameVisualState, 6=money number
    a.getlocal(0); a.emit(0x30)
    a.getlocal(1); a.pool(0x66, q['target']); a.emit(0x63); a.code += u30(2)
    a.getlocal(2); a.pool(0x66, q['name']); a.emit(0x63); a.code += u30(3)

    def set_fps(value: int) -> None:
        a.getlocal(0); a.getlex(q['stage']); a.push_number(value); a.pool(0x61, q['frameRate'])
        a.getlocal(0); a.pool(0x66, q['m_stateManager']); a.push_number(1); a.push_number(value); a.emit(0x9b)  # divide
        a.emit(0x4f); a.code += u30(q['setFrameRate']) + u30(1); a.emit(0x47)

    a.getlocal(3); a.pool(0x2c, strings['fps75']); a.branch(0x14, 'not75')
    set_fps(75)
    a.label('not75')
    a.getlocal(3); a.pool(0x2c, strings['fps120']); a.branch(0x14, 'not120')
    set_fps(120)
    a.label('not120')

    # Apply an arbitrary number from the input field.
    a.getlocal(3); a.pool(0x2c, strings['fpsApply']); a.branch(0x14, 'not_apply')
    a.getlocal(2); a.pool(0x66, q['parent']); a.emit(0x63); a.code += u30(4)
    a.pool(0x5d, q['Number'])
    a.getlocal(4); a.pool(0x2c, strings['fpsInput']); a.emit(0x46); a.code += u30(q['getChildByName']) + u30(1)
    # Number(text) is a conversion call (like the existing int/String calls
    # in this ABC), not an object allocation.
    a.pool(0x66, q['text']); a.emit(0x46); a.code += u30(q['Number']) + u30(1); a.emit(0x63); a.code += u30(4)
    # Keep malformed, zero, negative, and extreme input from reaching the
    # Stage.frameRate setter. Invalid custom values fall back to the default.
    a.pool(0x5d, q['isFinite']); a.getlocal(4); a.emit(0x46); a.code += u30(q['isFinite']) + u30(1)
    a.branch(0x12, 'invalid_custom')
    a.getlocal(4); a.push_number(1); a.branch(0x15, 'invalid_custom')
    a.getlocal(4); a.push_number(1000); a.branch(0x17, 'invalid_custom')
    a.branch(0x10, 'valid_custom')
    a.label('invalid_custom')
    a.push_number(75); a.setlocal(4)
    a.label('valid_custom')
    a.getlocal(0); a.getlex(q['stage']); a.getlocal(4); a.pool(0x61, q['frameRate'])
    a.getlocal(0); a.pool(0x66, q['m_stateManager']); a.push_number(1); a.getlocal(4); a.emit(0x9b)
    a.emit(0x4f); a.code += u30(q['setFrameRate']) + u30(1)
    a.emit(0x47)
    a.label('not_apply')

    # Set the current level's player money. The state type check keeps the
    # panel safe to open on menus/loading screens; the edit applies after a
    # level has created InGameVisualState.changedObjPlayer.
    a.getlocal(3); a.pool(0x2c, strings['moneyApply']); a.branch(0x14, 'not_money_apply')
    a.getlocal(0); a.pool(0x66, q['m_stateManager']); a.pool(0x66, q['topState'])
    a.emit(0xb2); a.code += u30(q['InGameVisualState'])
    a.branch(0x12, 'not_money_state')
    a.getlocal(0); a.pool(0x66, q['m_stateManager']); a.pool(0x66, q['topState']); a.emit(0x63); a.code += u30(5)
    a.getlocal(2); a.pool(0x66, q['parent']); a.emit(0x63); a.code += u30(4)
    a.pool(0x5d, q['Number'])
    a.getlocal(4); a.pool(0x2c, strings['moneyInput']); a.emit(0x46); a.code += u30(q['getChildByName']) + u30(1)
    a.pool(0x66, q['text']); a.emit(0x46); a.code += u30(q['Number']) + u30(1); a.emit(0x63); a.code += u30(6)
    a.pool(0x5d, q['isFinite']); a.getlocal(6); a.emit(0x46); a.code += u30(q['isFinite']) + u30(1)
    a.branch(0x12, 'invalid_money')
    a.getlocal(6); a.push_number(0); a.branch(0x15, 'invalid_money')
    a.branch(0x10, 'valid_money')
    a.label('invalid_money')
    a.push_number(0); a.setlocal(6)
    a.label('valid_money')
    a.getlocal(5); a.pool(0x66, q['changedObjPlayer']); a.getlocal(6); a.pool(0x61, q['money'])
    # Mark the AllStatistic object dirty so the normal HUD refresh displays
    # the new amount on the next game update.
    a.getlocal(5); a.pool(0x66, q['changedObjPlayer']); a.pool(0x66, q['money']); a.emit(0x26); a.pool(0x61, q['updated'])
    a.emit(0x47)
    a.label('not_money_state')
    a.label('not_money_apply')

    # Close the embedded panel.
    a.getlocal(3); a.pool(0x2c, strings['fpsClose']); a.branch(0x14, 'not_close')
    a.getlocal(2); a.pool(0x66, q['parent']); a.getlocal(2); a.emit(0x4f); a.code += u30(q['removeChild']) + u30(1)
    a.emit(0x47)
    a.label('not_close')

    # Drag the window by its named header.
    a.getlocal(3); a.pool(0x2c, strings['fpsHeader']); a.branch(0x14, 'stop_drag')
    a.getlocal(2); a.pool(0x66, q['parent']); a.emit(0x4f); a.code += u30(q['startDrag']) + u30(0)
    a.emit(0x47)
    a.label('stop_drag')

    # The stage mouse-up listener lands here too. Stop any active drag; if the
    # user clicked a non-control, this is harmless.
    a.getlocal(0); a.pool(0x2c, strings['fpsPanel']); a.emit(0x46); a.code += u30(q['getChildByName']) + u30(1); a.emit(0x63); a.code += u30(4)
    a.getlocal(4); a.branch(0x12, 'done')
    a.getlocal(4); a.emit(0x4f); a.code += u30(q['stopDrag']) + u30(0)
    a.label('done')
    a.emit(0x47)
    return a.finish()


def add_method(abc: dict, instance_index: int, name_qname: int,
               code: bytes, maxstack: int, locals_: int,
               params: list[int] | None = None,
               init_scope: int = 9, max_scope: int = 10) -> int:
    params = [2] if params is None else params
    method_index = len(abc['methods'])
    abc['methods'].append({
        'index': method_index, 'param_count': len(params), 'return': 0,
        'params': params, 'name': 0, 'flags': 0,
    })
    item = body(method_index, code, maxstack, locals_, init_scope, max_scope)
    item['index'] = len(abc['bodies'])
    abc['bodies'].append(item)
    abc['instances'][instance_index]['traits'].append(method_trait(name_qname, method_index))
    return method_index


def make_set_frame_rate_method(q: dict) -> bytes:
    a = Assembler()
    # GameEngine owns m_eftime in its private namespace. Keeping this tiny
    # setter on GameEngine lets the embedded menu change the timestep without
    # breaking that namespace's access rules.
    a.getlocal(0); a.emit(0x30)
    a.getlocal(0); a.getlocal(1); a.pool(0x61, q['m_eftime'])
    a.emit(0x47)
    return a.finish()


def patch_abc(original: bytes) -> bytes:
    abc = parse_abc(original)
    p = Pool(abc)

    # Existing public/package QNames and Main's private namespace are reused
    # wherever possible; only genuinely new names are added to the pools.
    q = {
        'Sprite': 51, 'TextField': 24, 'Number': 12,
        'stage': 3590, 'MouseEvent': 3, 'KeyboardEvent': 4,
        'CLICK': 3622, 'KEY_DOWN': 3623,
        'MOUSE_DOWN': 4154, 'MOUSE_UP': 3848,
        'keyCode': 3782, 'keyLocation': p.qname(1, 'keyLocation'),
        'frameRate': 3617, 'm_eftime': 291,
        'm_stateManager': 134, 'getChildByName': 3812,
        'addChild': 2000, 'removeChild': 2001,
        'graphics': 4104, 'beginFill': 4105, 'drawRect': 4106,
        'endFill': 4107, 'name': 4112, 'text': 697,
        'x': 1139, 'y': 1140, 'width': 417, 'height': 419,
        'border': 150, 'background': 698, 'textColor': 4311,
        'selectable': p.qname(1, 'selectable'),
        'type': 1263, 'mouseChildren': 3753, 'visible': 1144,
        'target': 3628, 'parent': 3657,
        'addEventListener': 3591,
        'startDrag': p.qname(1, 'startDrag'),
        'stopDrag': p.qname(1, 'stopDrag'),
        'setFrameRate': p.qname(1, 'setFrameRate'),
        'mouseX': 3834, 'mouseY': 3835,
        'Math': 3648, 'min': 3649, 'isFinite': 4236,
        'topState': 278, 'InGameVisualState': 43,
        'changedObjPlayer': 949, 'money': 1527, 'updated': 2945,
    }
    # Event type and field names that are already public but have no direct
    # QName in this ABC are supplied above through the existing pool.
    q.update({
        'fpsOpenName': p.qname(24, 'openFpsMenu'),
        'fpsEventName': p.qname(24, 'fpsMenuEvent'),
    })

    strings = {key: p.string(value) for key, value in {
        'fpsPanel': 'fpsPanel', 'fpsHeader': 'fpsHeader',
        'fpsInput': 'fpsInput', 'fps75': 'fps75', 'fps120': 'fps120',
        'fpsApply': 'fpsApply', 'fpsClose': 'fpsClose', 'moneyApply': 'moneyApply',
        'defaultFps': '75', 'defaultMoney': '0', 'moneyInput': 'moneyInput',
        'moneyLabel': 'Money amount', 'input': 'input', 'title': 'Stormy Castle FPS',
        'caption75': '75 FPS', 'caption120': '120 FPS', 'captionApply': 'Apply',
        'captionClose': 'Close', 'captionMoney': 'Set money',
        'footer': 'Right Shift opens; drag the header.',
    }.items()}
    colors = {
        'panel': p.int(0x263238), 'header': p.int(0x34495e),
        'button': p.int(0x3b82f6), 'apply': p.int(0x27ae60),
        'close': p.int(0xc0392b), 'white': p.int(0xffffff),
    }

    # Add the setter to GameEngine first. The two Main handlers then call it
    # through a public trait while the setter itself writes the private slot.
    game_engine_index = next(i for i, item in enumerate(abc['instances']) if item['name'] == 135)
    set_code = make_set_frame_rate_method(q)
    add_method(abc, game_engine_index, q['setFrameRate'], set_code,
               maxstack=2, locals_=2, params=[12], init_scope=4, max_scope=5)

    # Add the two embedded Main handlers before patching startGame so the
    # listener setup can reference their trait QNames.
    open_code = make_open_method(p, q, strings, colors)
    event_code = make_event_method(p, q, strings, colors)
    add_method(abc, 0, q['fpsOpenName'], open_code, maxstack=8, locals_=6,
               params=[4])
    add_method(abc, 0, q['fpsEventName'], event_code, maxstack=7, locals_=7)

    # The main class is Main (instance 0). Add stage listeners to the existing
    # startGame body, immediately before its return.
    setup = Assembler()
    # stage.addEventListener(KeyboardEvent.KEY_DOWN, this.openFpsMenu)
    setup.getlex(q['stage']); setup.getlex(q['KeyboardEvent']); setup.pool(0x66, q['KEY_DOWN']); setup.getlocal(0); setup.pool(0x66, q['fpsOpenName']); setup.emit(0x4f); setup.code += u30(q['addEventListener']) + u30(2)
    # stage.addEventListener(MouseEvent.MOUSE_UP, this.fpsMenuEvent)
    setup.getlex(q['stage']); setup.getlex(q['MouseEvent']); setup.pool(0x66, q['MOUSE_UP']); setup.getlocal(0); setup.pool(0x66, q['fpsEventName']); setup.emit(0x4f); setup.code += u30(q['addEventListener']) + u30(2)
    setup_code = setup.finish()
    start_body = next(b for b in abc['bodies'] if b['method'] == 6)
    if start_body['code'][-1:] != b'\x47':
        raise ValueError('Main.startGame does not end in returnvoid')
    start_body['code'] = start_body['code'][:-1] + setup_code + b'\x47'
    start_body['maxstack'] = max(start_body['maxstack'], 3)

    # GameData.FRAMERATE is the fixed timestep source used by GameEngine.
    game_data_body = next(b for b in abc['bodies'] if b['method'] == 1484)
    old = bytes([0x5e]) + u30(2770) + bytes([0x24, 30])
    new = bytes([0x5e]) + u30(2770) + bytes([0x24, 75])
    if old not in game_data_body['code']:
        raise ValueError('GameData.FRAMERATE initializer not found')
    game_data_body['code'] = game_data_body['code'].replace(old, new, 1)

    # The quake/shake counter is one of the few frame-counted visual effects.
    # Its original 10-frame values are scaled to 25 at 75 Hz, retaining the
    # original 1/3-second visual duration while the game tick remains timed.
    for b in abc['bodies']:
        code = b['code']
        needle = bytes([0x24, 10, 0x61]) + u30(1720)
        if needle in code:
            b['code'] = code.replace(needle, bytes([0x24, 25, 0x61]) + u30(1720))

    return serialize_abc(abc)


# ---------------------------------------------------------------------------
# SWF wrapper.

def swf_uncompressed(raw: bytes) -> bytes:
    if raw[:3] == b'CWS':
        return raw[:3].replace(b'C', b'F') + raw[3:8] + zlib.decompress(raw[8:])
    if raw[:3] == b'FWS':
        return raw
    raise ValueError(f'unsupported SWF signature {raw[:3]!r}')


def iter_tags(data: bytes):
    # Return positions as well as payload. The first 8 bytes are the SWF fixed
    # header; RECT plus frame rate/count precede the first tag.
    pos = 8
    nbits = data[pos] >> 3
    rect_len = (5 + 4 * nbits + 7) // 8
    pos += rect_len + 4
    while pos + 2 <= len(data):
        start = pos
        header = struct.unpack_from('<H', data, pos)[0]
        pos += 2
        code, length = header >> 6, header & 0x3f
        header_len = 2
        if length == 0x3f:
            length = struct.unpack_from('<I', data, pos)[0]
            pos += 4
            header_len = 6
        payload_start = pos
        payload_end = pos + length
        yield code, start, header_len, payload_start, payload_end
        pos = payload_end
        if code == 0:
            break


def write_tag(code: int, payload: bytes) -> bytes:
    if len(payload) < 0x3f:
        return struct.pack('<H', (code << 6) | len(payload)) + payload
    return struct.pack('<H', (code << 6) | 0x3f) + struct.pack('<I', len(payload)) + payload


def patch_swf(input_path: Path, output_path: Path) -> dict:
    raw = input_path.read_bytes()
    original_hash = hashlib.sha256(raw).hexdigest()
    swf = bytearray(swf_uncompressed(raw))

    # Fixed8 frame rate in the movie header.
    nbits = swf[8] >> 3
    rect_len = (5 + 4 * nbits + 7) // 8
    fps_offset = 8 + rect_len
    original_fps_fixed = struct.unpack_from('<H', swf, fps_offset)[0]
    struct.pack_into('<H', swf, fps_offset, 75 * 256)

    tags = []
    pos = 8 + rect_len + 4
    patched_abc = 0
    abc_before = None
    while pos + 2 <= len(swf):
        header = struct.unpack_from('<H', swf, pos)[0]
        pos0 = pos
        pos += 2
        code, length = header >> 6, header & 0x3f
        if length == 0x3f:
            length = struct.unpack_from('<I', swf, pos)[0]
            pos += 4
        payload = bytes(swf[pos:pos + length])
        pos += length
        if code == 82:
            nul = payload.find(b'\0', 4)
            if nul > 4:
                name = payload[4:nul].decode('utf-8', 'replace')
                if name == 'frame2':
                    abc_before = payload[nul + 1:]
                    payload = payload[:nul + 1] + patch_abc(abc_before)
                    patched_abc += 1
        tags.append(write_tag(code, payload))
        if code == 0:
            break

    if patched_abc != 1:
        raise ValueError(f'expected one frame2 DoABC tag, found {patched_abc}')

    body = bytes(swf[:8 + rect_len + 4]) + b''.join(tags)
    # Ensure the uncompressed SWF length field is correct.
    body = bytearray(body)
    struct.pack_into('<I', body, 4, len(body))
    compressed = b'CWS' + bytes([body[3]]) + struct.pack('<I', len(body)) + zlib.compress(bytes(body[8:]), 9)
    output_path.write_bytes(compressed)
    return {
        'original_sha256': original_hash,
        'output_sha256': hashlib.sha256(compressed).hexdigest(),
        'original_fps_fixed': original_fps_fixed,
        'output_bytes': len(compressed),
        'abc_before': len(abc_before or b''),
    }


def main(argv: list[str]) -> int:
    root = Path(__file__).resolve().parent
    source = root / '0.swf'
    output = root / 'Stormy Castle 75+ FPS.swf'
    if len(argv) > 1:
        output = Path(argv[1]).resolve()
    result = patch_swf(source, output)
    print('built', output)
    for key, value in result.items():
        print(f'{key}: {value}')
    if source.read_bytes() != Path(source).read_bytes():
        raise AssertionError('source changed')
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv))
