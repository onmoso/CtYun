from __future__ import annotations
import argparse
import getpass
import hashlib
import json
import os
import sys
import time
from websocket import create_connection, WebSocket

from .api import CtYunApi
from .models import LoginInfo, ConnectInfo, ConnectMessage
from .encryption import Encryption


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def is_running_in_container() -> bool:
    return os.path.exists("/.dockerenv")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--load-cache", action="store_true", help="Use cached connect.txt if available")
    args = parser.parse_args()

    print("Python CtYun v 0.1.0")

    t = LoginInfo(
        device_type="60",
        device_code=f"web_{os.urandom(16).hex()}",
        version="1020700001",
    )

    connect_text = ""
    use_cache = args.load_cache or os.getenv("LOAD_CACHE") == "1"
    if use_cache and os.path.exists("connect.txt"):
        with open("connect.txt", "r", encoding="utf-8") as f:
            connect_text = f.read()

    if not connect_text or '"desktopInfo":null' in connect_text:
        if is_running_in_container():
            t.user_phone = os.getenv("APP_USER")
            pwd = os.getenv("APP_PASSWORD")
            if not t.user_phone or not pwd:
                print("错误：必须设置环境变量 APP_USER 和 APP_PASSWORD")
                sys.exit(1)
            t.password = sha256_hex(pwd)
        else:
            t.user_phone = input("请输入账号：")
            t.password = sha256_hex(getpass.getpass("请输入密码："))

        api = CtYunApi(t)
        for i in range(3):
            if not api.login_async():
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
        connect_json = ConnectInfo.model_validate_json(connect_text)
    except Exception as e:
        print("connect数据校验错误" + str(e))
        sys.exit(1)

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
    t.desktop_id = str(desktop.desktopId)
    wss_host = desktop.clinkLvsOutHost
    message_bytes = json.dumps(msg.model_dump()).encode("utf-8")

    print("日志如果显示[发送保活消息成功。]才算成功。")
    while True:
        url = f"wss://{wss_host}/clinkProxy/{t.desktop_id}/MAIN"
        ws: WebSocket = create_connection(
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
            ws.send(message_bytes)
            time.sleep(0.5)
            ws.send_binary(bytes.fromhex("52454451020000020000001a0000000000000001000100000001000000120000000900000001080000"))
            # receive loop in foreground, emulate the C# behavior inside
            while True:
                frame = ws.recv()
                if isinstance(frame, str):
                    # text
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
            # after a minute, close and re-open to send keepalive
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
