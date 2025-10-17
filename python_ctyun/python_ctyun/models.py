from __future__ import annotations
from pydantic import BaseModel
from typing import List, Optional


class LoginInfo(BaseModel):
    desktop_id: Optional[str] = None
    session_id: Optional[str] = None
    device_type: str
    device_code: str
    user_account: Optional[str] = None
    password: Optional[str] = None
    user_phone: Optional[str] = None
    secret_key: Optional[str] = None
    user_id: Optional[int] = None
    tenant_id: Optional[int] = None
    version: str


class ClientDesktop(BaseModel):
    desktopId: str


class ClientInfoData(BaseModel):
    desktopList: List[ClientDesktop]


class ClientInfo(BaseModel):
    data: ClientInfoData


class DesktopInfo(BaseModel):
    host: str
    port: str
    clinkLvsOutHost: str
    caCert: str
    clientCert: str
    clientKey: str
    desktopId: int


class ConnectInfoData(BaseModel):
    desktopInfo: DesktopInfo


class ConnectInfo(BaseModel):
    data: ConnectInfoData


class ConnectMessage(BaseModel):
    type: int
    ssl: int
    host: str
    port: str
    ca: str
    cert: str
    key: str
    servername: str
