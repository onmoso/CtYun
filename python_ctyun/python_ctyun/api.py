from __future__ import annotations
import hashlib
import os
import time
from typing import Dict, List, Optional
import requests

from .models import LoginInfo, ClientInfo, ConnectInfo


class CtYunApi:
    base = "https://desk.ctyun.cn:8810"
    ocr_endpoint = "https://orc.xiaoleji.pro/ocr"

    def __init__(self, login: LoginInfo, session: Optional[requests.Session] = None):
        self.login = login
        self.session = session or requests.Session()
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36",
            "ctg-devicetype": login.device_type,
            "ctg-version": login.version,
            "ctg-devicecode": login.device_code,
            "referer": "https://pc.ctyun.cn/",
        }
        self.session.headers.update(headers)

    def _md5_hex(self, s: str) -> str:
        return hashlib.md5(s.encode("utf-8")).hexdigest()

    def _signed_headers(self) -> Dict[str, str]:
        now_ms = str(int(time.time() * 1000))
        sign_str = f"{self.login.device_type}{now_ms}{self.login.tenant_id}{now_ms}{self.login.user_id}{self.login.version}{self.login.secret_key}"
        return {
            "ctg-userid": str(self.login.user_id or ""),
            "ctg-tenantid": str(self.login.tenant_id or ""),
            "ctg-timestamp": now_ms,
            "ctg-requestid": now_ms,
            "ctg-signaturestr": self._md5_hex(sign_str),
        }

    def _captcha(self) -> str:
        try:
            print("正在识别验证码.")
            url = f"{self.base}/api/auth/client/captcha?height=36&width=85&userInfo={self.login.user_phone}&mode=auto&_t={int(time.time()*1000)}"
            img = self.session.get(url, timeout=20).content
            resp = requests.post(self.ocr_endpoint, files={"image": ("captcha.jpg", img)}, timeout=20)
            resp.raise_for_status()
            data = resp.json()
            code = data.get("data")
            print(f"识别结果：{code}")
            return code or ""
        except Exception as e:
            print(f"验证码获取识别错误：{e}")
            return ""

    def login_async(self) -> bool:
        code = self._captcha()
        form = {
            "userAccount": self.login.user_phone,
            "password": self.login.password,
            "sha256Password": self.login.password,
            "captchaCode": code,
        }
        # common fields
        form.update({
            "deviceCode": self.login.device_code,
            "deviceName": "Chrome浏览器",
            "deviceType": self.login.device_type,
            "deviceModel": "Windows NT 10.0; Win64; x64",
            "appVersion": "2.7.0",
            "sysVersion": "Windows NT 10.0; Win64; x64",
            "clientVersion": self.login.version,
        })
        r = self.session.post(f"{self.base}/api/auth/client/login", data=form, timeout=30)
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
            r = self.session.get(f"{self.base}/api/desktop/client/list", headers=h, timeout=20)
            r.raise_for_status()
            ci = ClientInfo.model_validate(r.json())
            return ci.data.desktopList[0].desktopId
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
        r = self.session.post(f"{self.base}/api/desktop/client/connect", data=form, headers=h, timeout=30)
        r.raise_for_status()
        return r.text
