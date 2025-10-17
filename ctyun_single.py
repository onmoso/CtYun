#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import hashlib
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import List, Optional, Dict

import requests
from websocket import create_connection

# ========= 配置（在此填写账号密码） =========
APP_USER = "你的账号"
APP_PASSWORD = "你的明文密码"
# 使用缓存（将 connect.txt 缓存到当前目录）
LOAD_CACHE = True
# ========================================

BASE = "https://desk.ctyun.cn:8810"
OCR_ENDPOINT = "https://orc.xiaoleji.pro/ocr"


# ---------- 工具函数 ----------
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


# ---------- 简易模型 ----------
@dataclass
class LoginInfo:
    desktop_id: Optional[str] = None
    session_id: Optional[str] = None
    device_type: str = "60"
    device_code: str = f"web_{os.urandom(16).hex()}"
    user_account: Optional[str] = None
    password: Optional[str] = None
    user_phone: Optional[str] = None
    secret_key: Optional[str] = None
    user_id: Optional[int] = None
    tenant_id: Optional[int] = None
    version: str = "1020700001"


# ---------- HTTP API ----------
class CtYunApi:
    def __init__(self, login: LoginInfo):
        self.login = login
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
                "ctg-devicetype": login.device_type,
                "ctg-version": login.version,
                "ctg-devicecode": login.device_code,
                "referer": "https://pc.ctyun.cn/",
            }
        )

    def _signed_headers(self) -> Dict[str, str]:
        now_ms = str(int(time.time() * 1000))
        sign_str = f"{self.login.device_type}{now_ms}{self.login.tenant_id}{now_ms}{self.login.user_id}{self.login.version}{self.login.secret_key}"
        return {
            "ctg-userid": str(self.login.user_id or ""),
            "ctg-tenantid": str(self.login.tenant_id or ""),
            "ctg-timestamp": now_ms,
            "ctg-requestid": now_ms,
            "ctg-signaturestr": md5_hex(sign_str),
        }

    def _captcha(self) -> str:
        try:
            print("正在识别验证码.")
            url = f"{BASE}/api/auth/client/captcha?height=36&width=85&userInfo={self.login.user_phone}&mode=auto&_t={int(time.time()*1000)}"
            img = self.session.get(url, timeout=20).content
            resp = requests.post(OCR_ENDPOINT, files={"image": ("captcha.jpg", img)}, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            code = data.get("data")
            print(f"识别结果：{code}")
            return code or ""
        except Exception as e:
            print(f"验证码获取识别错误：{e}")
            return ""

    def login(self) -> bool:
        code = self._captcha()
        form = {
            "userAccount": self.login.user_phone,
            "password": self.login.password,
            "sha256Password": self.login.password,
            "captchaCode": code,
            "deviceCode": self.login.device_code,
            "deviceName": "Chrome浏览器",
            "deviceType": self.login.device_type,
            "deviceModel": "Windows NT 10.0; Win64; x64",
            "appVersion": "2.7.0",
            "sysVersion": "Windows NT 10.0; Win64; x64",
            "clientVersion": self.login.version,
        }
        r = self.session.post(f"{BASE}/api/auth/client/login", data=form, timeout=30)
        r.raise_for_status()
        j = r.json()
        data = j.get("data", {}) if isinstance(j, dict) else {}
        if isinstance(data, dict) and "secretKey" in data:
            self.login.secret_key = data.get("secretKey")
            self.login.user_account = data.get("userAccount")
            self.login.user_id = data.get("userId")
            self.login.tenant_id = data.get("tenantId")
            print("登录成功.")
            return True
        else:
            print(j)
            return False

    def client_list(self) -> Optional[str]:
        try:
            h = self._signed_headers()
            r = self.session.get(f"{BASE}/api/desktop/client/list", headers=h, timeout=20)
            r.raise_for_status()
            j = r.json()
            desktop_list = j.get("data", {}).get("desktopList", [])
            return desktop_list[0]["desktopId"] if desktop_list else None
        except Exception as e:
            print(f"获取设备信息错误。{e}")
            return None

    def connect(self) -> str:
        form = {
            "objId": self.login.desktop_id,
            "objType": "0",
            "osType": "15",
            "deviceId": "60",
            "vdCommand": "",
            "ipAddress": "",
            "macAddress": "",
            "deviceCode": self.login.device_code,
            "deviceName": "Chrome浏览器",
            "deviceType": self.login.device_type,
            "deviceModel": "Windows NT 10.0; Win64; x64",
            "appVersion": "2.7.0",
            "sysVersion": "Windows NT 10.0; Win64; x64",
            "clientVersion": self.login.version,
        }
        h = self._signed_headers()
        r = self.session.post(f"{BASE}/api/desktop/client/connect", data=form, headers=h, timeout=30)
        r.raise_for_status()
        return r.text


# ---------- 加密（与 C# 同步的逻辑） ----------
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

    def dr_shift_to(self, e: int, t: "BigIntStruct") -> None:
        for n in range(e, self.t):
            if n - e < len(t.data):
                t.data[n - e] = self.data[n]
            else:
                t.data.append(self.data[n])
        t.t = max(self.t - e, 0)
        t.s = self.s

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

    def clamp(self) -> None:
        e = self.s & self.DM
        while self.t > 0 and self.data[self.t - 1] == e:
            self.t -= 1

    def copy_to(self, e: "BigIntStruct") -> None:
        e.data = self.data[:]
        e.t = self.t
        e.s = self.s

    def sub_to(self, e: "BigIntStruct", t: "BigIntStruct") -> None:
        n = 0
        r = 0
        o = min(e.t, self.t)
        t.data = [0] * max(self.t, e.t)
        idx = 0
        while idx < o:
            r += self.data[idx] - e.data[idx]
            t.data[idx] = r & self.DM
            idx += 1
            r >>= self.DB
        if e.t < self.t:
            while idx < self.t:
                r += self.data[idx]
                t.data[idx] = r & self.DM
                idx += 1
                r >>= self.DB
            r += self.s
        else:
            while idx < e.t:
                r -= e.data[idx]
                t.data[idx] = r & self.DM
                idx += 1
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
        # simplified division remainder reduction for our usage
        self.reduce(t)
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


class E:
    def __init__(self) -> None:
        self.e: int = 0
        self.n: BigIntStruct = BigIntStruct()

    def do_public(self, ek: "BigIntStruct") -> bytes:
        s = ek.mod_pow_int(self.e, self.n).to_string(16)
        if len(s) % 2 == 1:
            s = "0" + s
        return bytes.fromhex(s)


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
        r = os.urandom(20)
        i = e - 1 - len(r)
        l = i - len(t) - 1
        a = bytearray(i)
        # sha1("")
        base = hashlib.sha1(b"").digest()
        for k in range(len(base)):
            if k < len(a):
                a[k] = base[k]
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


# ---------- 运行主流程 ----------
def main() -> None:
    if not APP_USER or not APP_PASSWORD:
        print("请在文件顶部填写 APP_USER/APP_PASSWORD 后再运行。")
        sys.exit(1)

    t = LoginInfo(user_phone=APP_USER, password=sha256_hex(APP_PASSWORD))

    connect_text = ""
    if LOAD_CACHE and os.path.exists("connect.txt"):
        with open("connect.txt", "r", encoding="utf-8") as f:
            connect_text = f.read()

    if not connect_text or '"desktopInfo":null' in connect_text:
        api = CtYunApi(t)
        for i in range(3):
            if not api.login():
                print(f"重试第{i+1}次。")
                continue
            t.desktop_id = api.client_list()
            connect_text = api.connect()
            with open("connect.txt", "w", encoding="utf-8") as f:
                f.write(connect_text)
            break
        if not connect_text or '"desktopInfo":null' in connect_text:
            print("登录异常..connectText获取错误，检查电脑是否开机。")
            sys.exit(1)

    print("connect信息：" + connect_text)
    try:
        j = json.loads(connect_text)
        di = j["data"]["desktopInfo"]
    except Exception as e:
        print("connect数据校验错误" + str(e))
        sys.exit(1)

    msg = {
        "type": 1,
        "ssl": 1,
        "host": di["clinkLvsOutHost"].split(":")[0],
        "port": di["clinkLvsOutHost"].split(":")[1],
        "ca": di["caCert"],
        "cert": di["clientCert"],
        "key": di["clientKey"],
        "servername": f"{di['host']}:{di['port']}",
    }
    t.desktop_id = str(di["desktopId"])  # for url
    wss_host = di["clinkLvsOutHost"]

    print("日志如果显示[发送保活消息成功。]才算成功。")
    while True:
        url = f"wss://{wss_host}/clinkProxy/{t.desktop_id}/MAIN"
        ws = create_connection(
            url,
            subprotocols=["binary"],
            header=[
                "Origin: https://pc.ctyun.cn",
                "Pragma: no-cache",
                "Cache-Control: no-cache",
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36",
            ],
            sslopt={"cert_reqs": 0},
        )
        try:
            print("连接服务器中...")
            print("连接成功!")
            ws.send(json.dumps(msg))
            time.sleep(0.5)
            ws.send_binary(bytes.fromhex("52454451020000020000001a0000000000000001000100000001000000120000000900000001080000"))
            while True:
                frame = ws.recv()
                if isinstance(frame, str):
                    continue
                data: bytes = frame
                hexs = data.hex().upper()
                if hexs.startswith("5245445102"):
                    print("收到保活校验消息: " + hexs)
                    e = Encryption()
                    out = e.execute(data)
                    print("发送保活消息.")
                    ws.send_binary(out)
                    print("发送保活消息成功。")
                else:
                    if "00000000" not in hexs:
                        print("收到消息: " + hexs.replace("000000000000", ""))
            # 循环不中断，按 Ctrl+C 退出
        except Exception as ex:
            print("WebSocket error: " + str(ex))
        finally:
            try:
                ws.close()
            except Exception:
                pass
            print("准备关闭连接重新发送保活信息.")
            time.sleep(60)


if __name__ == "__main__":
    main()
