from __future__ import annotations
from dataclasses import dataclass
import os
import random
from typing import List


class Encryption:
    def __init__(self) -> None:
        self.buffers: List[bytes] = []
        self.auth_mechanism: int = 1

    def execute(self, key: bytes) -> bytes:
        self._resolve_inbound_data(key)
        pubkey = self._pub_key()
        buffer = self._L(128, "\x00", pubkey)
        return self._to_buffer(buffer)

    def _to_buffer(self, buffer: bytes) -> bytes:
        return self.auth_mechanism.to_bytes(4, "little") + buffer

    def _resolve_inbound_data(self, data: bytes) -> None:
        self.buffers.append(data[16:])

    def _read_24(self, s: bytes, start_idx: int) -> int:
        b = s[start_idx:start_idx+3]
        return (b[0] << 16) | (b[1] << 8) | b[2]

    def _pub_key(self) -> "E":
        e = self.buffers[0][32:32+129]
        l = E()
        l.n.from_string(e)
        l.e = self._read_24(self.buffers[0], 163)
        return l

    def _sha1_js(self, s: str) -> bytes:
        # Minimal reimplementation compatible with C# Sha1JsEquivalent.S for empty string use case
        # In original code, S("") is used to fill a block. For Python, use hashlib.sha1("").digest() repeated.
        import hashlib
        h = hashlib.sha1(s.encode("latin1")).digest()
        return h

    def _P(self, e: bytearray, t: bytes) -> None:
        import hashlib
        n = 0
        o = 0
        while o < len(e):
            i = t + n.to_bytes(4, "big")
            a = hashlib.sha1(i).digest()
            for r in range(len(a)):
                if o >= len(e):
                    break
                e[o] = a[r]
                o += 1
            n += 1

    def _L(self, e: int, t: str, pubkey: "E") -> bytes:
        import hashlib
        r = os.urandom(20)
        i = e - 1 - len(r)
        l = i - len(t) - 1
        a = bytearray(i)
        resulta = self._sha1_js("")
        for k in range(len(resulta)):
            if k < len(a):
                a[k] = resulta[k]
        a[l] = 1
        a[l+1:l+1+len(t)] = t.encode("latin1")
        c = bytearray(i)
        self._P(c, r)
        for o in range(len(c)):
            a[o] ^= c[o]
        u = bytearray(20)
        self._P(u, a)
        r_mut = bytearray(r)
        for o in range(len(u)):
            r_mut[o] ^= u[o]
        d = b"\x00" + bytes(r_mut) + bytes(a)
        le = BigIntStruct()
        le.from_string(d)
        le.clamp()
        return pubkey.do_public(le)


class E:
    def __init__(self) -> None:
        self.e: int = 0
        self.n: BigIntStruct = BigIntStruct()

    def do_public(self, ek: "BigIntStruct") -> bytes:
        s = ek.mod_pow_int(self.e, self.n).to_string(16)
        # ensure even length
        if len(s) % 2 == 1:
            s = "0" + s
        return bytes.fromhex(s)


class BigIntStruct:
    def __init__(self) -> None:
        self.DB: int = 28
        self.DM: int = (1 << 28) - 1
        self.DV: int = 1 << 28
        self.data: List[int] = []
        self.t: int = 0
        self.s: int = 0

    def from_string(self, e: bytes) -> None:
        n = 8
        self.t = 0
        self.s = 0
        i = 0
        for idx in range(len(e) - 1, -1, -1):
            l = e[idx] & 0xFF
            if i == 0:
                self.data.append(l)
                self.t += 1
            elif i + n > self.DB:
                last = self.data[self.t - 1]
                last |= (l & ((1 << (self.DB - i)) - 1)) << i
                self.data[self.t - 1] = last
                self.data.append((l >> (self.DB - i)))
                self.t += 1
            else:
                last = self.data[self.t - 1]
                last |= l << i
                self.data[self.t - 1] = last
            i += n
            if i >= self.DB:
                i -= self.DB

    def to_string(self, e: int) -> str:
        if e == 16:
            t = 4
        elif e == 8:
            t = 3
        elif e == 2:
            t = 1
        elif e == 32:
            t = 5
        elif e == 4:
            t = 2
        else:
            raise ValueError("unsupported base")
        r = (1 << t) - 1
        started = False
        result = ""
        a = self.t
        l = self.DB - a * self.DB % t
        if a - 1 >= 0:
            a -= 1
            if l < self.DB:
                n = self.data[a] >> l
                if n > 0:
                    started = True
                    result = format(n, "x")
            while a >= 0:
                if l < t:
                    n = (self.data[a] & ((1 << l) - 1)) << (t - l)
                    a -= 1
                    if a >= 0:
                        n |= self.data[a] >> (l + self.DB - t)
                        l = l + self.DB - t
                else:
                    n = (self.data[a] >> (l - t)) & r
                    l -= t
                    if l <= 0:
                        l += self.DB
                        a -= 1
                if n > 0:
                    started = True
                if started:
                    result += format(n, "x")
        return result if started else "0"

    def multiply_to(self, e: "BigIntStruct", t: "BigIntStruct") -> None:
        n = self
        r = e
        o = n.t
        t.t = o + r.t
        for idx in range(o - 1, -1, -1):
            t.data[idx:idx+1] = [0]
        for o in range(r.t):
            t.data[o + n.t:o + n.t + 1] = [n.am(0, r.data[o], t, o, 0, n.t)]
        t.s = 0
        t.clamp()

    def dr_shift_to(self, e: int, t: "BigIntStruct") -> None:
        for n in range(e, self.t):
            if n - e < len(t.data):
                t.data[n - e] = self.data[n]
            else:
                t.data.append(self.data[n])
        t.t = max(self.t - e, 0)
        t.s = self.s

    def clamp(self) -> None:
        e = self.s & self.DM
        while self.t > 0 and self.data[self.t - 1] == e:
            self.t -= 1

    def mod_pow_int(self, e: int, t: "BigIntStruct") -> "BigIntStruct":
        n = V()
        n.v(t)
        return self.exp(e, n)

    def exp(self, e: int, t: "V") -> "BigIntStruct":
        o = t.convert(self)
        i = self._bit_length(e) - 1
        n = BigIntStruct()
        r = BigIntStruct()
        o.copy_to(n)
        while i > 0:
            t.sqr_to(n, r)
            if (e & (1 << (i - 1))) > 0:
                t.mul_to(r, o, n)
            else:
                s = n
                n = r
                r = s
            i -= 1
        return t.revert(n)

    def square_to(self, e: "BigIntStruct") -> None:
        t = self
        n = e
        n.t = 2 * t.t
        if len(n.data) < n.t + 2:
            n.data.extend([0] * (n.t + 2 - len(n.data)))
        for i in range(n.t):
            n.data[i] = 0
        for k in range(t.t - 1):
            r = t.am(k, t.data[k], n, 2 * k, 0, 1)
            j = k + t.t
            n.data[j] += t.am(k + 1, 2 * t.data[k], n, 2 * k + 1, r, t.t - k - 1)
            if n.data[j] >= t.DV:
                n.data[j] -= t.DV
                if j + 1 >= len(n.data):
                    n.data.append(0)
                n.data[j + 1] = 1
        if n.t > 0:
            n.data[n.t - 1] += t.am(t.t - 1, t.data[t.t - 1], n, 2 * (t.t - 1), 0, 1)
        n.s = 0
        n.clamp()

    def copy_to(self, e: "BigIntStruct") -> None:
        e.data = self.data[:]
        e.t = self.t
        e.s = self.s

    def div_rem_to(self, e: "BigIntStruct", n: "BigIntStruct") -> None:
        r = e
        o = self
        s = self.s
        c = e.s
        # constants matching C# implementation
        F1 = 24
        F2 = 4
        FV = 4503599627370496  # 2^52
        # helper for bit-length-like calculation used by original code
        def _h(x: int) -> int:
            n = 1
            t = x >> 16
            if t != 0:
                x = t
                n += 16
            t = x >> 8
            if t != 0:
                x = t
                n += 8
            t = x >> 4
            if t != 0:
                x = t
                n += 4
            t = x >> 2
            if t != 0:
                x = t
                n += 2
            t = x >> 1
            if t != 0:
                x = t
                n += 1
            return n
        u = self.DB - _h(r.data[r.t - 1]) if r.t > 0 else 0
        i = BigIntStruct()
        r.l_shift_to(u, i)
        o.l_shift_to(u, n)
        d = i.t
        if d == 0:
            return
        f = i.data[d - 1]
        if f == 0:
            return
        p = (f << F1)
        if d > 1:
            p += (i.data[d - 2] >> F2)
        m = FV / p
        v = (1 << F1) / p
        g = 1 << F2
        y = n.t
        b = y - d
        w = BigIntStruct()
        i.dl_shift_to(b, w)
        if n.compare_to(w) >= 0:
            if n.t < len(n.data):
                n.data[n.t] = 1
            else:
                n.data.append(1)
            n.t += 1
            n.sub_to(w, n)
        ONE = BigIntStruct()
        if len(ONE.data) == 0:
            ONE.data.append(1)
        else:
            ONE.data[0] = 1
        ONE.t = 1
        # w = ONE << (d * DB) - i (not strictly needed beyond normalization parity)
        i2 = BigIntStruct()
        ONE.dl_shift_to(d, i2)
        i2.sub_to(i, i)
        while i.t < d:
            if i.t < len(i.data):
                i.data[i.t] = 0
            else:
                i.data.append(0)
            i.t += 1
        while b >= 0:
            y -= 1
            if n.data[y] == f:
                qhat = self.DM
            else:
                ny = n.data[y]
                ny1 = n.data[y - 1] if y - 1 >= 0 else 0
                qhat = int((ny * m) + ((ny1 + g) * v))
            if (n.data[y] + i.am(0, qhat, n, b, 0, d)) < qhat:
                i.dl_shift_to(b, w)
                n.sub_to(w, n)
                qhat -= 1
                while n.data[y] < qhat:
                    n.sub_to(w, n)
                    qhat -= 1
            b -= 1
        n.t = d
        n.clamp()
        if u > 0:
            n.r_shift_to(u, n)

    def r_shift_to(self, e: int, t: "BigIntStruct") -> None:
        t.s = self.s
        n = e // self.DB
        if n >= self.t:
            t.t = 0
        else:
            r = e % self.DB
            o = self.DB - r
            i = (1 << r) - 1
            t.data = [0] * (self.t - n)
            t.data[0] = self.data[n] >> r
            for a in range(n + 1, self.t):
                t.data[a - n - 1] |= (self.data[a] & i) << o
                t.data[a - n] = self.data[a] >> r
            if r > 0:
                t.data[self.t - n - 1] |= (self.s & i) << o
            t.t = self.t - n
            t.clamp()

    def am(self, e: int, t: int, n: "BigIntStruct", r: int, o: int, i: int) -> int:
        a = t & 0x3FFF
        l = t >> 14
        while i > 0:
            s = self.data[e] & 0x3FFF
            c = self.data[e] >> 14
            u = l * s + c * a
            temp = a * s + ((u & 0x3FFF) << 14) + (n.data[r] if r < len(n.data) else 0) + o
            o = (temp >> 28) + (u >> 14) + l * c
            if r < len(n.data):
                n.data[r] = temp & 0xFFFFFFF
            else:
                n.data.append(temp & 0xFFFFFFF)
            r += 1
            e += 1
            i -= 1
        return o

    def sub_to(self, e: "BigIntStruct", t: "BigIntStruct") -> None:
        n = 0
        r = 0
        o = min(e.t, self.t)
        t.data = [0] * max(self.t, e.t)
        while n < o:
            r += self.data[n] - e.data[n]
            t.data[n] = r & self.DM
            n += 1
            r >>= self.DB
        if e.t < self.t:
            while n < self.t:
                r += self.data[n]
                t.data[n] = r & self.DM
                n += 1
                r >>= self.DB
            r += self.s
        else:
            while n < e.t:
                r -= e.data[n]
                t.data[n] = r & self.DM
                n += 1
                r >>= self.DB
            r -= e.s
        t.s = -1 if r < 0 else 0
        if r < -1:
            t.data.append(self.DV + r)
        elif r > 0:
            t.data.append(r)
        t.t = len(t.data)
        t.clamp()

    def compare_to(self, e: "BigIntStruct") -> int:
        t = self.s - e.s
        if t != 0:
            return t
        n = self.t
        t = n - e.t
        if t != 0:
            return t
        for idx in range(n - 1, -1, -1):
            t = self.data[idx] - e.data[idx]
            if t != 0:
                return t
        return 0

    def dl_shift_to(self, e: int, t: "BigIntStruct") -> None:
        for n in range(self.t - 1, -1, -1):
            if n + e < len(t.data):
                t.data[n + e] = self.data[n]
            else:
                t.data.append(self.data[n])
        for n in range(e - 1, -1, -1):
            if n < len(t.data):
                t.data[n] = 0
            else:
                t.data.append(0)
        t.t = self.t + e
        t.s = self.s

    def l_shift_to(self, e: int, t: "BigIntStruct") -> None:
        r = e % self.DB
        o = self.DB - r
        i = (1 << o) - 1
        a = e // self.DB
        l = (self.s << r) & self.DM
        t.data = [0] * (self.t + a + 2)
        for n in range(self.t - 1, -1, -1):
            t.data[n + a + 1] = (self.data[n] >> o) | l
            l = (self.data[n] & i) << r
        t.data[a] = l
        t.t = self.t + a + 1
        t.s = self.s
        t.clamp()

    def inv_digit(self) -> int:
        if self.t < 1:
            return 0
        e = self.data[0]
        if (e & 1) == 0:
            return 0
        inv = e & 3
        inv = (inv * (2 - ((e & 15) * inv))) & 15
        inv = (inv * (2 - ((e & 255) * inv))) & 255
        inv = (inv * (2 - ((e & 0xFFFF) * inv & 0xFFFF))) & 0xFFFF
        inv = (inv * (2 - (e * inv % self.DV))) % self.DV
        return self.DV - inv if inv > 0 else -inv

    def _bit_length(self, e: int) -> int:
        if e == 0:
            return 0
        n = 0
        while e:
            n += 1
            e >>= 1
        return n


class V:
    def __init__(self) -> None:
        self.m = BigIntStruct()
        self.mp = 0
        self.mpl = 0
        self.mph = 0
        self.um = 0
        self.mt2 = 0

    def v(self, e: BigIntStruct) -> None:
        self.m = e
        self.mp = self.m.inv_digit()
        self.mpl = self.mp & 0x7FFF
        self.mph = self.mp >> 15
        self.mt2 = 2 * e.t
        self.um = (1 << (e.DB - 15)) - 1

    def convert(self, e: BigIntStruct) -> BigIntStruct:
        t = BigIntStruct()
        e.dl_shift_to(self.m.t, t)
        t.div_rem_to(self.m, t)
        return t

    def sqr_to(self, e: BigIntStruct, t: BigIntStruct) -> None:
        e.square_to(t)
        self.reduce(t)

    def reduce(self, e: BigIntStruct) -> None:
        while e.t <= self.mt2:
            if e.t < len(e.data):
                e.data[e.t] = 0
            else:
                e.data.append(0)
            e.t += 1
        for t_idx in range(self.m.t):
            n = e.data[t_idx] & 0x7FFF
            r = (n * self.mpl + (((n * self.mph + ((e.data[t_idx] >> 15) * self.mpl) & self.um) << 15))) & e.DM
            k = t_idx + self.m.t
            carry = self.m.am(0, r, e, t_idx, 0, self.m.t)
            if k < len(e.data):
                e.data[k] += carry
            else:
                e.data.append(carry)
            while e.data[k] >= e.DV:
                e.data[k] -= e.DV
                k += 1
                if k >= len(e.data):
                    e.data.append(0)
                e.data[k] += 1
        e.clamp()
        e.dr_shift_to(self.m.t, e)
        if e.compare_to(self.m) >= 0:
            e.sub_to(self.m, e)

    def mul_to(self, e: BigIntStruct, t: BigIntStruct, n: BigIntStruct) -> None:
        e.multiply_to(t, n)
        self.reduce(n)

    def revert(self, e: BigIntStruct) -> BigIntStruct:
        t = BigIntStruct()
        e.copy_to(t)
        self.reduce(t)
        return t
