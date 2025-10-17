from __future__ import annotations
import json
import os
import time
from typing import Any, Dict

from .api import CtYunApi
from .models import LoginInfo, ConnectInfo, ConnectMessage
from .encryption import Encryption
from websocket import create_connection


def _sha256_hex(s: str) -> str:
    import hashlib
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.lower() in ("1", "true", "yes")


def handler(event: Any, context: Any) -> Dict[str, Any]:
    # event can be dict or JSON string depending on platform
    if isinstance(event, str):
        try:
            event = json.loads(event)
        except Exception:
            event = {}
    event = event or {}

    # Inputs: user (or APP_USER), password (or APP_PASSWORD), loadCache/LOAD_CACHE
    user = event.get("user") or os.getenv("APP_USER")
    password = event.get("password") or os.getenv("APP_PASSWORD")
    load_cache = event.get("loadCache")
    if load_cache is None:
        load_cache = _bool_env("LOAD_CACHE", False)

    if not user or not password:
        return {"ok": False, "error": "missing user/password"}

    login = LoginInfo(
        device_type="60",
        device_code=f"web_{os.urandom(16).hex()}",
        version="1020700001",
        user_phone=user,
        password=_sha256_hex(password),
    )

    connect_text = ""
    if load_cache and os.path.exists("/tmp/connect.txt"):
        try:
            with open("/tmp/connect.txt", "r", encoding="utf-8") as f:
                connect_text = f.read()
        except Exception:
            connect_text = ""

    api = CtYunApi(login)

    # If no valid cache, perform login and connect
    if not connect_text or '"desktopInfo":null' in connect_text:
        for _ in range(3):
            if not api.login_async():
                continue
            login.desktop_id = api.client_list()
            connect_text = api.connect()
            try:
                with open("/tmp/connect.txt", "w", encoding="utf-8") as f:
                    f.write(connect_text)
            except Exception:
                pass
            break
        if not connect_text or '"desktopInfo":null' in connect_text:
            return {"ok": False, "error": "connect info invalid; check desktop state"}

    # Prepare websocket handshake payload
    try:
        connect_json = ConnectInfo.model_validate_json(connect_text)
    except Exception as e:
        return {"ok": False, "error": f"connect parse error: {e}"}

    desktop = connect_json.data.desktopInfo
    msg = ConnectMessage(
        type=1,
        ssl=1,
        host=desktop.clinkLvsOutHost.split(":")[0],
        port=desktop.clinkLvsOutHost.split(":")[1],
        ca=desktop.caCert,
        cert=desktop.clientCert,
        key=desktop.clientKey,
        servername=f"{desktop.host}:{desktop.port}",
    )
    login.desktop_id = str(desktop.desktopId)
    wss_host = desktop.clinkLvsOutHost

    # In serverless, maintain a short keepalive cycle and return last status
    url = f"wss://{wss_host}/clinkProxy/{login.desktop_id}/MAIN"
    start = time.time()
    sent_keepalive = False
    try:
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
        ws.send(json.dumps(msg.model_dump()))
        time.sleep(0.5)
        ws.send_binary(bytes.fromhex("52454451020000020000001a0000000000000001000100000001000000120000000900000001080000"))
        # Read frames up to ~10 seconds to fit typical cloud function time budgets
        while time.time() - start < 10:
            frame = ws.recv()
            if isinstance(frame, str):
                continue
            data: bytes = frame
            if data[:5].hex().upper().startswith("5245445102"):
                e = Encryption()
                out = e.execute(data)
                ws.send_binary(out)
                sent_keepalive = True
                break
        try:
            ws.close()
        except Exception:
            pass
    except Exception as ex:
        return {"ok": False, "error": str(ex)}

    return {
        "ok": True,
        "sentKeepalive": sent_keepalive,
        "desktopId": login.desktop_id,
    }
